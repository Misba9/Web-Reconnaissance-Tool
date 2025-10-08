#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer


async def virust(hostname, conf_path, session, print_formatted_result_func):
	with open(f'{conf_path}/keys.json', 'r', encoding='utf-8') as keyfile:
		json_read = keyfile.read()

	json_load = loads(json_read)
	vt_key = json_load['virustotal']

	if vt_key is not None:
		print_formatted_result_func('Requesting VirusTotal for subdomains')
		url = f'https://www.virustotal.com/api/v3/domains/{hostname}/subdomains'
		vt_headers = {
			'x-apikey': vt_key
		}
		try:
			async with session.get(url, headers=vt_headers) as resp:
				status = resp.status
				if status == 200:
					json_data = await resp.text()
					json_read = loads(json_data)
					domains = json_read['data']
					tmp_list = []
					for i in range(0, len(domains)):
						tmp_list.append(domains[i]['id'])
					print_formatted_result_func(f'VirusTotal found {len(tmp_list)} subdomains!', {'Subdomains found': len(tmp_list)})
					parent.found.extend(tmp_list)
				else:
					print_formatted_result_func(f'VirusTotal returned status: {status}')
					log_writer(f'[virustotal_subs] Status = {status}')
		except Exception as exc:
			print_formatted_result_func(f'VirusTotal Exception: {exc}')
			log_writer(f'[virustotal_subs] Exception = {exc}')
	else:
		print_formatted_result_func('Skipping VirusTotal: API key not found!')
		log_writer('[virustotal_subs] API key not found')
	log_writer('[virustotal_subs] Completed')
