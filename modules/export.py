#!/usr/bin/env python3

import sys

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def export(output, data):
    if output['format'] != 'txt':
        print(f'{R}[-] {C}Invalid Output Format, Valid Formats : {W}txt')
        sys.exit()

    fname = output['file']
    with open(fname, 'w', encoding='utf-8') as outfile:
        txt_export(data, outfile)


def txt_unpack(outfile, val, indent_level=0):
    indent = "    " * indent_level
    if isinstance(val, list):
        for item in val:
            if isinstance(item, (dict, list)):
                txt_unpack(outfile, item, indent_level + 1)
            else:
                outfile.write(f'{indent}- {item}\n')
    elif isinstance(val, dict):
        for sub_key, sub_val in val.items():
            if sub_key == 'exported':
                continue
            if isinstance(sub_val, (dict, list)):
                outfile.write(f'{indent}{sub_key}:\n')
                txt_unpack(outfile, sub_val, indent_level + 1)
            else:
                outfile.write(f'{indent}{sub_key}: {sub_val}\n')


def txt_export(data, outfile):
    for key, val in data.items():
        if key.startswith('module'):
            if not val['exported']:
                outfile.write(f'\n{key.replace('module-', '').replace('_', ' ').title()}:\n')
                outfile.write(f'{"=" * (len(key) - 7)}\n\n')
                txt_unpack(outfile, val)
                val['exported'] = True
        elif key.startswith('Type'):
            outfile.write(f'\n{data[key]}\n')
            outfile.write(f'{"=" * len(data[key])}\n\n')
        else:
            outfile.write(f'{key}: {val}\n')
