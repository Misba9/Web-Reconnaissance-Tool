#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer


async def fb_cert(hostname, conf_path, session, print_formatted_result_func):
	with open(f'{conf_path}/keys.json', 'r', encoding='utf-8') as keyfile:
		json_read = keyfile.read()

	json_load = loads(json_read)
	fb_key = json_load['facebook']

	if fb_key is not None:
		print_formatted_result_func('Requesting Facebook for subdomains')
		url = 'https://graph.facebook.com/certificates'
		fb_params = {
			'query': hostname,
			'fields': 'domains',
			'access_token': fb_key
		}
		try:
			async with session.get(url, params=fb_params) as resp:
				status = resp.status
				if status == 200:
					json_data = await resp.text()
					json_read = loads(json_data)
					domains = json_read['data']
					print_formatted_result_func(f'Facebook found {len(domains)} subdomains!', {'Subdomains found': len(domains)})
					for i in range(0, len(domains)):
						parent.found.extend(json_read['data'][i]['domains'])
				else:
					print_formatted_result_func(f'Facebook returned status: {status}')
					log_writer(f'[fb_subs] Status = {status}, expected 200')
		except Exception as exc:
			print_formatted_result_func(f'Facebook Exception: {exc}')
			log_writer(f'[fb_subs] Exception = {exc}')
	else:
		print_formatted_result_func('Skipping Facebook: API key not found!')
		log_writer('[fb_subs] API key not found')
	log_writer('[fb_subs] Completed')
