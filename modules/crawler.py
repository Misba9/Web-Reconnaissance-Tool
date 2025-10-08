#!/usr/bin/env python3

import re
import bs4
import lxml
import asyncio
import requests
import threading
import tldextract
from modules.export import export
from modules.write_log import log_writer
requests.packages.urllib3.disable_warnings()

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

user_agent = {'User-Agent': 'ReconBoss/1.0'}

# Initialize as sets to avoid append/add confusion
total = set()
r_total = set()
sm_total = set()
js_total = set()
css_total = set()
int_total = set()
ext_total = set()
img_total = set()
js_crawl_total = set()
sm_crawl_total = set()


def crawler(target, output, data, print_formatted_result_func):
	global r_url, sm_url
	print_formatted_result_func('Starting Crawler...')

	try:
		rqst = requests.get(target, headers=user_agent, verify=False, timeout=10)
	except Exception as exc:
		print_formatted_result_func(f'Exception during crawling: {exc}')
		log_writer(f'[crawler] Exception = {exc}')
		return

	status = rqst.status_code
	if status == 200:
		page = rqst.content
		soup = bs4.BeautifulSoup(page, 'lxml')

		protocol = target.split('://')
		protocol = protocol[0]
		temp_tgt = target.split('://')[1]
		pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{2,5}'
		custom = bool(re.match(pattern, temp_tgt))
		if custom:
			r_url = f'{protocol}://{temp_tgt}/robots.txt'
			sm_url = f'{protocol}://{temp_tgt}/sitemap.xml'
			base_url = f'{protocol}://{temp_tgt}'
		else:
			ext = tldextract.extract(target)
			if ext.subdomain:
				hostname = f'{ext.subdomain}.{ext.domain}.{ext.suffix}'
			else:
				hostname = ext.registered_domain
			base_url = f'{protocol}://{hostname}'
			r_url = f'{base_url}/robots.txt'
			sm_url = f'{base_url}/sitemap.xml'

		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		tasks = asyncio.gather(
			robots(r_url, base_url, data, output, print_formatted_result_func),
			sitemap(sm_url, data, output, print_formatted_result_func),
			css(target, data, soup, output, print_formatted_result_func),
			js_scan(target, data, soup, output, print_formatted_result_func),
			internal_links(target, data, soup, output, print_formatted_result_func),
			external_links(target, data, soup, output, print_formatted_result_func),
			images(target, data, soup, output, print_formatted_result_func),
			sm_crawl(data, output, print_formatted_result_func),
			js_crawl(data, output, print_formatted_result_func))
		loop.run_until_complete(tasks)
		loop.close()
		stats(output, data, soup, print_formatted_result_func)
		log_writer('[crawler] Completed')
	else:
		print_formatted_result_func(f'Received status code: {status}, expected 200')
		log_writer(f'[crawler] Status code = {status}, expected 200')


def url_filter(target, link):
	if all([link.startswith('/') is True, link.startswith('//') is False]):
		ret_url = target + link
		return ret_url

	if link.startswith('//') is True:
		ret_url = link.replace('//', 'http://')
		return ret_url

	if all([
		link.find('//') == -1,
		link.find('../') == -1,
		link.find('./') == -1,
		link.find('http://') == -1,
		link.find('https://') == -1]
	):
		ret_url = f'{target}/{link}'
		return ret_url

	if all([
		link.find('http://') == -1,
		link.find('https://') == -1]
	):
		ret_url = link.replace('//', 'http://')
		ret_url = link.replace('../', f'{target}/')
		ret_url = link.replace('./', f'{target}/')
		return ret_url
	return link


async def robots(robo_url, base_url, data, output, print_formatted_result_func):
	global r_total
	print_formatted_result_func(f'Looking for robots.txt', end='', flush=True)

	try:
		r_rqst = requests.get(robo_url, headers=user_agent, verify=False, timeout=10)
		r_sc = r_rqst.status_code
		if r_sc == 200:
			print_formatted_result_func(f'Found robots.txt')
			print_formatted_result_func(f'Extracting robots Links', end='', flush=True)
			r_page = r_rqst.text
			r_scrape = r_page.split('\n')
			for entry in r_scrape:
				if any([
					entry.find('Disallow') == 0,
					entry.find('Allow') == 0,
					entry.find('Sitemap') == 0]):

					url = entry.split(': ', 1)[1].strip()
					tmp_url = url_filter(base_url, url)

					if tmp_url is not None:
						r_total.add(url_filter(base_url, url))

					if url.endswith('xml'):
						sm_total.add(url)

			print_formatted_result_func(f'{len(r_total)} robots.txt links found')
			exporter(data, output, r_total, 'robots')

		elif r_sc == 404:
			print_formatted_result_func(f'robots.txt not found')

		else:
			print_formatted_result_func(f'robots.txt returned status code: {r_sc}')

	except Exception as exc:
		print_formatted_result_func(f'Exception during robots.txt scan: {exc}')
		log_writer(f'[crawler.robots] Exception = {exc}')


async def sitemap(target_url, data, output, print_formatted_result_func):
	global sm_total
	print_formatted_result_func(f'Looking for sitemap.xml', end='', flush=True)
	try:
		sm_rqst = requests.get(target_url, headers=user_agent, verify=False, timeout=10)
		sm_sc = sm_rqst.status_code
		if sm_sc == 200:
			print_formatted_result_func(f'Found sitemap.xml')
			print_formatted_result_func(f'Extracting sitemap Links', end='', flush=True)
			sm_page = sm_rqst.content
			sm_soup = bs4.BeautifulSoup(sm_page, 'xml')
			links = sm_soup.find_all('loc')
			for url in links:
				url = url.get_text()
				if url is not None:
					sm_total.add(url)

			print_formatted_result_func(f'{len(sm_total)} sitemap links found')
			exporter(data, output, sm_total, 'sitemap')
		elif sm_sc == 404:
			print_formatted_result_func(f'sitemap.xml not found')
		else:
			print_formatted_result_func(f'sitemap.xml returned status code: {sm_sc}')
	except Exception as exc:
		print_formatted_result_func(f'Exception during sitemap.xml scan: {exc}')
		log_writer(f'[crawler.sitemap] Exception = {exc}')


async def css(target, data, soup, output, print_formatted_result_func):
	global css_total
	print_formatted_result_func(f'Extracting CSS Links', end='', flush=True)
	css_links = soup.find_all('link', href=True)

	for link in css_links:
		url = link.get('href')
		if url is not None and '.css' in url:
			css_total.add(url_filter(target, url))

	print_formatted_result_func(f'{len(css_total)} CSS links found')
	exporter(data, output, css_total, 'css')


async def js_scan(target, data, soup, output, print_formatted_result_func):
	global js_total
	print_formatted_result_func(f'Extracting Javascript Links', end='', flush=True)
	scr_tags = soup.find_all('script', src=True)

	for link in scr_tags:
		url = link.get('src')
		if url is not None and '.js' in url:
			tmp_url = url_filter(target, url)
			if tmp_url is not None:
				js_total.add(tmp_url)

	print_formatted_result_func(f'{len(js_total)} Javascript links found')
	exporter(data, output, js_total, 'javascripts')


async def internal_links(target, data, soup, output, print_formatted_result_func):
	global int_total
	print_formatted_result_func(f'Extracting Internal Links', end='', flush=True)

	ext = tldextract.extract(target)
	domain = ext.registered_domain

	links = soup.find_all('a')
	for link in links:
		url = link.get('href')
		if url is not None:
			if domain in url:
				int_total.add(url)

	print_formatted_result_func(f'{len(int_total)} Internal links found')
	exporter(data, output, int_total, 'internal_urls')


async def external_links(target, data, soup, output, print_formatted_result_func):
	global ext_total
	print_formatted_result_func(f'Extracting External Links', end='', flush=True)

	ext = tldextract.extract(target)
	domain = ext.registered_domain

	links = soup.find_all('a')
	for link in links:
		url = link.get('href')
		if url is not None:
			if domain not in url and 'http' in url:
				ext_total.add(url)

	print_formatted_result_func(f'{len(ext_total)} External links found')
	exporter(data, output, ext_total, 'external_urls')


async def images(target, data, soup, output, print_formatted_result_func):
	global img_total
	print_formatted_result_func(f'Extracting Images', end='', flush=True)
	image_tags = soup.find_all('img')

	for link in image_tags:
		url = link.get('src')
		if url is not None and len(url) > 1:
			img_total.add(url_filter(target, url))

	print_formatted_result_func(f'{len(img_total)} Images found')
	exporter(data, output, img_total, 'images')


async def sm_crawl(data, output, print_formatted_result_func):
	global sm_crawl_total
	print_formatted_result_func(f'Crawling Sitemaps', end='', flush=True)

	threads = []

	def fetch(site_url):
		try:
			sm_rqst = requests.get(site_url, headers=user_agent, verify=False, timeout=10)
			sm_sc = sm_rqst.status_code
			if sm_sc == 200:
				sm_data = sm_rqst.content.decode()
				sm_soup = bs4.BeautifulSoup(sm_data, 'xml')
				links = sm_soup.find_all('loc')
				for url in links:
					url = url.get_text()
					if url is not None:
						sm_crawl_total.add(url)
			elif sm_sc == 404:
				pass # print_formatted_result_func(f'Sitemap not found: {site_url}')
			else:
				pass # print_formatted_result_func(f'Sitemap returned status {sm_sc}: {site_url}')
		except Exception as exc:
			print_formatted_result_func(f'Exception during sitemap crawling: {exc}')
			log_writer(f'[crawler.sm_crawl] Exception = {exc}')

	for site_url in sm_total:
		if site_url != sm_url:
			if site_url.endswith('xml') is True:
				task = threading.Thread(target=fetch, args=[site_url])
				task.daemon = True
				threads.append(task)
				task.start()

	for thread in threads:
		thread.join()

	print_formatted_result_func(f'{len(sm_crawl_total)} URLs found inside sitemaps')
	exporter(data, output, sm_crawl_total, 'urls_inside_sitemap')


async def js_crawl(data, output, print_formatted_result_func):
	global js_crawl_total
	print_formatted_result_func(f'Crawling Javascripts', end='', flush=True)

	threads = []

	def fetch(js_url):
		try:
			js_rqst = requests.get(js_url, headers=user_agent, verify=False, timeout=10)
			js_sc = js_rqst.status_code
			if js_sc == 200:
				js_data = js_rqst.content.decode()
				js_data = js_data.split(';')
				for line in js_data:
					if any(['http://' in line, 'https://' in line]):
						found = re.findall(r'\"(http[s]?://.*?)\"', line)
						for item in found:
							if len(item) > 8:
								js_crawl_total.add(item)
		except Exception as exc:
			print_formatted_result_func(f'Exception during JavaScript crawling: {exc}')
			log_writer(f'[crawler.js_crawl] Exception = {exc}')

	for js_url in js_total:
		task = threading.Thread(target=fetch, args=[js_url])
		task.daemon = True
		threads.append(task)
		task.start()

	for thread in threads:
		thread.join()

	print_formatted_result_func(f'{len(js_crawl_total)} URLs found inside Javascripts')
	exporter(data, output, js_crawl_total, 'urls_inside_js')


def exporter(data, output, list_name, file_name):
	data[f'module-crawler-{file_name}'] = {'links': list(list_name)}
	data[f'module-crawler-{file_name}'].update({'exported': False})
	fname = f'{output["directory"]}/{file_name}.{output["format"]}'
	output['file'] = fname
	export(output, data)


def stats(output, data, soup, print_formatted_result_func):
	global total

	total.update(r_total)
	total.update(sm_total)
	total.update(css_total)
	total.update(js_total)
	total.update(js_crawl_total)
	total.update(sm_crawl_total)
	total.update(int_total)
	total.update(ext_total)
	total.update(img_total)

	print_formatted_result_func(f'Total Unique Links Extracted: {len(total)}')

	if output != 'None':
		if len(total) != 0:
			data['module-crawler-stats'] = {'Total Unique Links Extracted': str(len(total))}
			try:
				target_title = soup.title.string
			except AttributeError:
				target_title = 'None'
			data['module-crawler-stats'].update({'Title ': str(target_title)})

			data['module-crawler-stats'].update(
				{
					'total_urls_robots': len(r_total),
					'total_urls_sitemap': len(sm_total),
					'total_urls_css': len(css_total),
					'total_urls_js': len(js_total),
					'total_urls_in_js': len(js_crawl_total),
					'total_urls_in_sitemaps': len(sm_crawl_total),
					'total_urls_internal': len(int_total),
					'total_urls_external': len(ext_total),
					'total_urls_images': len(img_total),
					'total_urls': len(total)
				})
			data['module-crawler-stats'].update({'exported': False})