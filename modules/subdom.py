#!/usr/bin/env python3

import aiohttp
import asyncio
from re import match
from modules.export import export
from modules.write_log import log_writer
from modules.subdomain_modules.bevigil_subs import bevigil
from modules.subdomain_modules.anubis_subs import anubisdb
from modules.subdomain_modules.thminer_subs import thminer
from modules.subdomain_modules.fb_subs import fb_cert
from modules.subdomain_modules.virustotal_subs import virust
from modules.subdomain_modules.shodan_subs import shodan
from modules.subdomain_modules.certspot_subs import certspot
from modules.subdomain_modules.wayback_subs import machine
from modules.subdomain_modules.crtsh_subs import crtsh
from modules.subdomain_modules.htarget_subs import hackertgt

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

found = []


async def query(hostname, tout, conf_path, print_formatted_result_func):
	timeout = aiohttp.ClientTimeout(total=tout)
	async with aiohttp.ClientSession(timeout=timeout) as session:
		await asyncio.gather(
			bevigil(hostname, conf_path, session, print_formatted_result_func),
			anubisdb(hostname, session, print_formatted_result_func),
			thminer(hostname, session, print_formatted_result_func),
			fb_cert(hostname, conf_path, session, print_formatted_result_func),
			virust(hostname, conf_path, session, print_formatted_result_func),
			shodan(hostname, conf_path, session, print_formatted_result_func),
			certspot(hostname, session, print_formatted_result_func),
			machine(hostname, session, print_formatted_result_func),
			hackertgt(hostname, session, print_formatted_result_func),
			crtsh(hostname, print_formatted_result_func)
		)
	await session.close()


def subdomains(hostname, tout, output, data, conf_path, print_formatted_result_func):
	global found
	result = {}

	print_formatted_result_func('Starting Sub-Domain Enumeration...')

	loop = asyncio.new_event_loop()
	asyncio.set_event_loop(loop)
	loop.run_until_complete(query(hostname, tout, conf_path, print_formatted_result_func))
	loop.close()

	found = [item for item in found if item.endswith(hostname)]
	valid = r"^[A-Za-z0-9._~()'!*:@,;+?-]*$"
	found = [item for item in found if match(valid, item)]
	found = set(found)
	total = len(found)

	if found:
		print_formatted_result_func('Sub-Domain Results:', {'Subdomains': list(found)[:20]})

		if len(found) > 20:
			print_formatted_result_func('Results truncated to first 20 subdomains.')

	print_formatted_result_func(f'Total Unique Sub Domains Found: {total}')

	if output != 'None':
		result['Links'] = list(found)
		result.update({'exported': False})
		data['module-Subdomain Enumeration'] = result
		fname = f'{output["directory"]}/subdomains.{output["format"]}'
		output['file'] = fname
		export(output, data)
	log_writer('[subdom] Completed')
