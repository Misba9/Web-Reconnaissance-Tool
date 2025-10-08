#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads
import modules.subdom as parent
from modules.write_log import log_writer


async def thminer(hostname, session, print_formatted_result_func):
	print_formatted_result_func('Requesting ThreatMiner for subdomains')
	url = 'https://api.threatminer.org/v2/domain.php'
	thm_params = {
		'q': hostname,
		'rt': '5'
	}
	try:
		async with session.get(url, params=thm_params) as resp:
			status = resp.status
			if status == 200:
				output = await resp.text()
				json_out = loads(output)
				subd = json_out['results']
				print_formatted_result_func(f'ThreatMiner found {len(subd)} subdomains!', {'Subdomains found': len(subd)})
				parent.found.extend(subd)
			else:
				print_formatted_result_func(f'ThreatMiner returned status: {status}')
				log_writer(f'[thminer_subs] Status = {status}, expected 200')
	except Exception as exc:
		print_formatted_result_func(f'ThreatMiner Exception: {exc}')
		log_writer(f'[thminer_subs] Exception = {exc}')
	log_writer('[thminer_subs] Completed')
