#!/usr/bin/env python3

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

import modules.subdom as parent
from modules.write_log import log_writer


async def machine(hostname, session, print_formatted_result_func):
    print_formatted_result_func('Requesting Wayback Machine for subdomains')
    url = f'http://web.archive.org/cdx/search/cdx?url=*.{hostname}/*&output=txt&fl=original&collapse=urlkey'
    try:
        async with session.get(url) as resp:
            status = resp.status
            if status == 200:
                raw_data = await resp.text()
                lines = raw_data.split('\n')
                tmp_list = []
                for line in lines:
                    subdomain = line.replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
                    if len(subdomain) > len(hostname):
                        tmp_list.append(subdomain)
                print_formatted_result_func(f'Wayback Machine found {len(tmp_list)} subdomains!', {'Subdomains found': len(tmp_list)})
                parent.found.extend(tmp_list)
            else:
                print_formatted_result_func(f'Wayback Machine returned status: {status}')
                log_writer(f'[wayback_subs] Status = {status}, expected 200')
    except Exception as exc:
        print_formatted_result_func(f'Wayback Machine Exception: {exc}')
        log_writer(f'[wayback_subs] Exception = {exc}')
    log_writer('[wayback_subs] Completed')
