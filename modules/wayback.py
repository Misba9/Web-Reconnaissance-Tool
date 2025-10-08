#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import json
import requests
from datetime import date
from modules.export import export
from modules.write_log import log_writer


def timetravel(target, data, output, print_formatted_result_func):
	wayback_total = []
	result = {}
	is_avail = False
	domain_query = f'{target}/*'

	curr_yr = date.today().year
	last_yr = curr_yr - 5

	print_formatted_result_func('Starting Wayback Machine scan...')
	print_formatted_result_func('Checking availability on Wayback Machine')
	wm_avail = 'http://archive.org/wayback/available'
	avail_data = {'url': target}

	try:
		check_rqst = requests.get(wm_avail, params=avail_data, timeout=10)
		check_sc = check_rqst.status_code
		if check_sc == 200:
			check_data = check_rqst.text
			json_chk_data = json.loads(check_data)
			avail_data = json_chk_data['archived_snapshots']
			if avail_data:
				print_formatted_result_func('Wayback Machine: Available')
			else:
				print_formatted_result_func('Wayback Machine: Not Available')
		else:
			print_formatted_result_func(f'Wayback Machine availability check returned status: {check_sc}')
			log_writer(f'[wayback] Status = {check_sc}, expected 200')

		if avail_data:
			print_formatted_result_func('Fetching URLs from Wayback Machine')
			wm_url = 'http://web.archive.org/cdx/search/cdx'

			payload = {
				'url': domain_query,
				'fl': 'original',
				'fastLatest': 'true',
				'from': str(last_yr),
				'to': str(curr_yr)
			}

			rqst = requests.get(wm_url, params=payload, timeout=10)
			r_sc = rqst.status_code
			if r_sc == 200:
				r_data = rqst.text
				if data:
					r_data = set(r_data.split('\n'))
					print_formatted_result_func(f'{len(r_data)} URLs fetched from Wayback Machine', {'URLs fetched': len(r_data)})
					wayback_total.extend(r_data)

					if output != 'None':
						result.update({'links': list(r_data)})
						result.update({'exported': False})
						data['module-wayback_urls'] = result
						fname = f'{output["directory"]}/wayback_urls.{output["format"]}'
						output['file'] = fname
						export(output, data)
				else:
					print_formatted_result_func('No URLs found from Wayback Machine')
			else:
				print_formatted_result_func(f'Wayback Machine URL fetch returned status: {r_sc}')
	except Exception as exc:
		print_formatted_result_func(f'Wayback Machine Exception: {exc}')
		log_writer(f'[wayback] Exception = {exc}')
	log_writer('[wayback] Completed')
