#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer


async def anubisdb(hostname, session, print_formatted_result_func):
	print_formatted_result_func('Requesting AnubisDB for subdomains')
	url = f'https://jldc.me/anubis/subdomains/{hostname}'
	try:
		async with session.get(url) as resp:
			status = resp.status
			if status == 200:
				output = await resp.text()
				json_out = loads(output)
				parent.found.extend(json_out)
				print_formatted_result_func(f'AnubisDB found {len(json_out)} subdomains!', {'Subdomains found': len(json_out)})
			else:
				print_formatted_result_func(f'AnubisDB returned status: {status}')
				log_writer(f'[anubis_subs] Status = {status}, expected 200')
	except Exception as exc:
		print_formatted_result_func(f'AnubisDB Exception: {exc}')
	log_writer('[anubis_subs] Completed')
