#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer


async def shodan(hostname, conf_path, session, print_formatted_result_func):
	with open(f'{conf_path}/keys.json', 'r', encoding='utf-8') as keyfile:
		json_read = keyfile.read()

	json_load = loads(json_read)
	sho_key = json_load['shodan']

	if sho_key is not None:
		print_formatted_result_func('Requesting Shodan for subdomains')
		url = f'https://api.shodan.io/dns/domain/{hostname}?key={sho_key}'

		try:
			async with session.get(url) as resp:
				status = resp.status
				if status == 200:
					json_data = await resp.text()
					json_read = loads(json_data)
					domains = json_read['subdomains']
					tmp_list = []
					for i in range(0, len(domains)):
						tmp_list.append(f'{domains[i]}.{hostname}')
					print_formatted_result_func(f'Shodan found {len(tmp_list)} subdomains!', {'Subdomains found': len(tmp_list)})
					parent.found.extend(tmp_list)
				else:
					print_formatted_result_func(f'Shodan returned status: {status}')
					log_writer(f'[shodan_subs] Status = {status}, expected 200')
		except Exception as exc:
			print_formatted_result_func(f'Shodan Exception: {exc}')
			log_writer(f'[shodan_subs] Exception = {exc}')
	else:
		print_formatted_result_func('Skipping Shodan: API key not found!')
		log_writer('[shodan_subs] API key not found')
	log_writer('[shodan_subs] Completed')
