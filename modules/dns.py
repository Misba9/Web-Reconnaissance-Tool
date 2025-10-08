#!/usr/bin/env python3

import dnslib
from modules.export import export
from modules.write_log import log_writer

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow

def dnsrec(domain, output, data, print_formatted_result_func):
    """
    Perform DNS enumeration for a given domain.

    Args:
        domain (str): The domain to perform DNS enumeration on.
        output (str): The output configuration for saving the results.
        data (dict): The data dictionary to store the results.
    """
    result = {}
    print_formatted_result_func('Starting DNS Enumeration...')
    dns_records = ['A', 'AAAA', 'ANY', 'CAA', 'CNAME', 'MX', 'NS', 'TXT']
    full_ans = []

    # Query DNS Records for various record types
    for dns_record in dns_records:
        query = dnslib.DNSRecord.question(domain, dns_record)
        try:
            pkt = query.send('8.8.8.8', 53, tcp='UDP')
            ans = dnslib.DNSRecord.parse(pkt)
            ans = str(ans)
            ans = ans.split('\n')
            full_ans.extend(ans)
        except ConnectionRefusedError as exc:
            print_formatted_result_func(f'Exception during DNS query: {exc}. Server is probably not listening!')
            log_writer(f'[dns] Exception = {exc}')
            return

    full_ans = set(full_ans)
    dns_found = []

    # Print DNS Records found
    for entry in full_ans:
        if not entry.startswith(';'):
            dns_found.append(entry)

    if not dns_found:
        print_formatted_result_func('DNS Records Not Found!')
        if output != 'None':
            result.setdefault('dns', ['DNS Records Not Found'])
    else:
        print_formatted_result_func('DNS Records:', {'Records': dns_found})
        for entry in dns_found:
            if output != 'None':
                result.setdefault('dns', []).append(entry)

    dmarc_target = f'_dmarc.{domain}'
    query = dnslib.DNSRecord.question(dmarc_target, 'TXT')
    pkt = query.send('8.8.8.8', 53, tcp='UDP')
    dmarc_ans = dnslib.DNSRecord.parse(pkt)
    dmarc_ans = str(dmarc_ans)
    dmarc_ans = dmarc_ans.split('\n')
    dmarc_found = []

    # Query DMARC Record
    for entry in dmarc_ans:
        if entry.startswith('_dmarc'):
            dmarc_found.append(entry)

    if not dmarc_found:
        print_formatted_result_func('DMARC Record Not Found!')
        if output != 'None':
            result.setdefault('dmarc', ['DMARC Record Not Found!'])
    else:
        print_formatted_result_func('DMARC Records:', {'Records': dmarc_found})
        for entry in dmarc_found:
            if output != 'None':
                result.setdefault('dmarc', []).append(entry)
    result.update({'exported': False})

    # Export Results if specified
    if output != 'None':
        data['module-DNS Enumeration'] = result
        fname = f'{output["directory"]}/dns_records.{output["format"]}'
        output['file'] = fname
        export(output, data)
    log_writer('[dns] Completed')
