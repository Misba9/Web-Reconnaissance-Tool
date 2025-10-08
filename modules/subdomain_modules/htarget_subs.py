#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import modules.subdom as parent
from modules.write_log import log_writer


async def hackertgt(hostname, session, print_formatted_result_func):
	print_formatted_result_func('Requesting HackerTarget for subdomains')
	url = f'https://api.hackertarget.com/hostsearch/?q={hostname}'
	try:
		async with session.get(url) as resp:
			status = resp.status
			if status == 200:
				data = await resp.text()
				data_list = data.split('\n')
				tmp_list = []
				for line in data_list:
					subdomain = line.split(',')[0]
					tmp_list.append(subdomain)
				print_formatted_result_func(f'HackerTarget found {len(tmp_list)} subdomains!', {'Subdomains found': len(tmp_list)})
				parent.found.extend(tmp_list)
			else:
				print_formatted_result_func(f'HackerTarget returned status: {status}')
				log_writer(f'[htarget_subs] Status = {status}, expected 200')
	except Exception as exc:
		print_formatted_result_func(f'HackerTarget Exception: {exc}')
		log_writer(f'[htarget_subs] Exception = {exc}')
	log_writer('[htarget_subs] Completed')
