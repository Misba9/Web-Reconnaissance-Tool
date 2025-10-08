#!/usr/bin/env python3

import asyncio
from json import load
from modules.export import export
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

# this get_whois function is an async function that takes domain and server as arguments
# it creates a connection to the whois server using asyncio.open_connection
# it sends the domain to the server and reads the response in chunks
# if the response is empty, it breaks the loop
# it then decodes the response and checks if the response contains 'No match for'	
# if it does, it sets the whois_result to None
# it then splits the response into two parts using '>>>' as the separator
# it then sets the whois_result['whois'] to the first part of the response
# it then returns the whois_result

async def get_whois(domain, server):
	whois_result = {}
	reader, writer = await asyncio.open_connection(server, 43)
	writer.write((domain + '\r\n').encode())

	raw_resp = b''
	while True:
		chunk = await reader.read(4096)
		if not chunk:
			break
		raw_resp += chunk

	writer.close()
	await writer.wait_closed()
	raw_result = raw_resp.decode()

	if 'No match for' in raw_result:
		whois_result = None

	res_parts = raw_result.split('>>>', 1)
	whois_result['whois'] = res_parts[0]
	return whois_result


def whois_lookup(domain, tld, script_path, output, data, print_formatted_result_func):
	result = {}
	db_path = f'{script_path}/whois_servers.json'
	with open(db_path, 'r', encoding='utf-8') as db_file:
		db_json = load(db_file)
	print_formatted_result_func('Starting Whois Lookup...')

	try:
		whois_sv = db_json[tld]
		whois_info = asyncio.run(get_whois(domain, whois_sv))
		if whois_info and 'whois' in whois_info:
			print_formatted_result_func('Whois Information:', {'Raw Whois Data': whois_info['whois']})
			result.update(whois_info)
		else:
			print_formatted_result_func('No Whois information found for this domain.')
	except KeyError:
		print_formatted_result_func(f'Error: This domain suffix ({tld}) is not supported for Whois lookup.')
		result.update({'Error': 'This domain suffix is not supported.'})
		log_writer('[whois] Exception = This domain suffix is not supported.')
	except Exception as exc:
		print_formatted_result_func(f'Error during Whois lookup: {exc}')
		result.update({'Error': str(exc)})
		log_writer(f'[whois] Exception = {exc}')

	result.update({'exported': False})

	if output != 'None':
		fname = f'{output["directory"]}/whois.{output["format"]}'
		output['file'] = fname
		data['module-whois'] = result
		export(output, data)
	log_writer('[whois] Completed')
