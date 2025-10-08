#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

from json import loads, dumps
import modules.subdom as parent
from modules.write_log import log_writer


async def bevigil(hostname, conf_path, session, print_formatted_result_func):
    with open(f'{conf_path}/keys.json', 'r', encoding='utf-8') as keyfile:
        json_read = keyfile.read()

    json_load = loads(json_read)
    try:
        bevigil_key = json_load['bevigil']
    except KeyError:
        log_writer('[bevigil_subs] key missing in keys.json')
        with open(f'{conf_path}/keys.json', 'w', encoding='utf-8') as outfile:
            json_load['bevigil'] = None
            bevigil_key = None
            outfile.write(
                dumps(json_load, sort_keys=True, indent=4)
            )

    if bevigil_key is not None:
        print_formatted_result_func('Requesting BeVigil for subdomains')
        url = f"https://osint.bevigil.com/api/{hostname}/subdomains/"
        header = {"X-Access-Token": bevigil_key}

        try:
            async with session.get(url, headers=header) as resp:
                status = resp.status
                if status == 200:
                    json_data: list = await resp.json()
                    subdomains = json_data.get("subdomains")
                    print_formatted_result_func(f'BeVigil found {len(subdomains)} subdomains!', {'Subdomains found': len(subdomains)})
                    parent.found.extend(subdomains)
                else:
                    print_formatted_result_func(f'BeVigil returned status: {status}')
                    log_writer(f'[bevigil_subs] Status = {status}, expected 200')

        except Exception as exc:
            print_formatted_result_func(f'BeVigil Exception: {exc}')
            log_writer(f'[bevigil_subs] Exception = {exc}')
    else:
        print_formatted_result_func('Skipping BeVigil: API key not found!')
        log_writer('[bevigil_subs] API key not found')
    log_writer('[bevigil_subs] Completed')
