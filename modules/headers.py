#!/usr/bin/env python3

import requests
from modules.export import export
from modules.write_log import log_writer
requests.packages.urllib3.disable_warnings()

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def headers(target, output, data, print_formatted_result_func):
	result = {}
	print_formatted_result_func('Initiating Header Scan', {})
	try:
		rqst = requests.get(target, verify=False, timeout=10)
		for key, val in rqst.headers.items():
			print_formatted_result_func(f'{key}: {val}')
			if output != 'None':
				result.update({key: val})
	except Exception as exc:
		print_formatted_result_func(f'Error during Header Scan: {exc}')
		if output != 'None':
			result.update({'Exception': str(exc)})
		log_writer(f'[headers] Exception = {exc}')
	result.update({'exported': False})

	if output != 'None':
		fname = f'{output["directory"]}/headers.{output["format"]}'
		output['file'] = fname
		data['module-headers'] = result
		export(output, data)
	log_writer('[headers] Completed')
