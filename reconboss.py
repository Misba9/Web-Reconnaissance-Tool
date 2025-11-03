#!/usr/bin/env python3

import os
import sys

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white

from modules.write_log import log_writer
log_writer('Importing config...')
import settings as config

home = config.home
usr_data = config.usr_data
conf_path = config.conf_path
path_to_script = config.path_to_script
src_conf_path = config.src_conf_path
meta_file_path = config.meta_file_path

log_writer(
	f'PATHS = HOME:{home}, SCRIPT_LOC:{path_to_script},\
	METADATA:{meta_file_path}, KEYS:{config.keys_file_path},\
	CONFIG:{config.conf_file_path}, LOG:{config.log_file_path}'
)

import argparse
# argparse is a Python module that allows you to easily parse command-line arguments and options in your code.
VERSION = '1'
log_writer(f'ReconBoss v{VERSION}')

parser = argparse.ArgumentParser()
parser = argparse.ArgumentParser(description=f'ReconBoss - The Last Web Recon Tool You Will Need | v{VERSION}')
parser.add_argument('url', help='Target URL')
parser.add_argument('--headers', help='Header Information', action='store_true')
parser.add_argument('--sslinfo', help='SSL Certificate Information', action='store_true')
parser.add_argument('--whois', help='Whois Lookup', action='store_true')
parser.add_argument('--crawl', help='Crawl Target', action='store_true')
parser.add_argument('--dns', help='DNS Enumeration', action='store_true')
parser.add_argument('--sub', help='Sub-Domain Enumeration', action='store_true')
parser.add_argument('--dir', help='Directory Search', action='store_true')
parser.add_argument('--wayback', help='Wayback URLs', action='store_true')
parser.add_argument('--ps', help='Fast Port Scan', action='store_true')
parser.add_argument('--full', help='Full Recon', action='store_true')

ext_help = parser.add_argument_group('Extra Options')
ext_help.add_argument('-dt', type=int, help='Number of threads for directory enum [ Default : 30 ]')
ext_help.add_argument('-pt', type=int, help='Number of threads for port scan [ Default : 50 ]')
ext_help.add_argument('-T', type=float, help='Request Timeout [ Default : 30.0 ]')
ext_help.add_argument('-w', help='Path to Wordlist [ Default : wordlists/dirb_common.txt ]')
ext_help.add_argument('-r', action='store_true', help='Allow Redirect [ Default : False ]')
ext_help.add_argument('-s', action='store_false', help='Toggle SSL Verification [ Default : True ]')
ext_help.add_argument('-sp', type=int, help='Specify SSL Port [ Default : 443 ]')
ext_help.add_argument('-d', help='Custom DNS Servers [ Default : 1.1.1.1 ]')
ext_help.add_argument('-e', help='File Extensions [ Example : txt, xml, php ]')
ext_help.add_argument('-o', help='Export Format [ Default : txt ]')
ext_help.set_defaults(
	dt=config.dir_enum_th,
	pt=config.port_scan_th,
	T=config.timeout,
	w=config.dir_enum_wlist,
	r=config.dir_enum_redirect,
	s=config.dir_enum_sslv,
	sp=config.ssl_port,
	d=config.dir_enum_dns,
	e=config.dir_enum_ext,
	o=config.export_fmt
)

try:
	args = parser.parse_args()
except SystemExit:
	log_writer('[ReconBoss] Help menu accessed')
	log_writer(f'{"-" * 30}')
	sys.exit()

target = args.url
headinfo = args.headers
sslinfo = args.sslinfo
whois = args.whois
crawl = args.crawl
dns = args.dns
dirrec = args.dir
wback = args.wayback
pscan = args.ps
full = args.full
threads = args.dt
pscan_threads = args.pt
tout = args.T
wdlist = args.w
redir = args.r
sslv = args.s
sslp = args.sp
dserv = args.d
filext = args.e
subd = args.sub
output = args.o

import socket
import datetime
import ipaddress
import tldextract
from json import loads
import pytz

type_ip = False
data = {}

def print_formatted_result(message, data_dict=None):
    ist = pytz.timezone('Asia/Kolkata')
    now = datetime.datetime.now(ist)
    timestamp = now.strftime('%d-%m-%Y %H:%M:%S IST')
    
    output_message = f"[{timestamp}] {message}"
    print(f'{output_message}')

    if data_dict:
        for key, value in data_dict.items():
            if isinstance(value, list):
                if value:
                    print(f'    - {key}:')
                    for item in value:
                        print(f'        - {item}')
            else:
                if value is not None and str(value).strip() != '':
                    print(f'    - {key}: {value}')

def banner():
    with open(meta_file_path, 'r', encoding='utf-8') as metadata:
        json_data = loads(metadata.read())
        twitter_url = json_data['twitter']
        comms_url = json_data['comms']

    art = r'''
                ____                           ____                 
               / __ \___  _________  ____     / __ )____  __________
              / /_/ / _ \/ ___/ __ \/ __ \   / __  / __ \/ ___/ ___/
             / _, _/  __/ /__/ /_/ / / / /  / /_/ / /_/ (__  |__  ) 
            /_/ |_|\___/\___/\____/_/ /_/  /_____/\____/____/____/  
                                                                    
                             +-+-+-+-+-+ +-+-+-+-+
                             |R|e|c|o|n| |B|o|s|s|
                             +-+-+-+-+-+ +-+-+-+-+
                                                                                                                 
'''
    print(f'{G}{art}{W}\n')
    print(f'{G}[>]{C} Created By   :{W} ahmed')
    # print(f'{G} |--->{C} Twitter   :{W} {twitter_url}')
    print(f'{G} |--->{C} Community :{W} {comms_url}')
    print(f'{G}[>]{C} Version      :{W} {VERSION}\n')

try:
	banner()

	if not target.startswith(('http', 'https')):
		print(f'{R}[-] {C}Protocol Missing, Include {W}http:// {C}or{W} https:// \n')
		log_writer(f'Protocol missing in {target}, exiting')
		sys.exit(1)

	if target.endswith('/'):
		target = target[:-1]

	print_formatted_result(f"Target URL: {target}")
	ext = tldextract.extract(target)
	domain = ext.registered_domain
	if not domain:
		domain = ext.domain
	domain_suffix = ext.suffix

	if ext.subdomain:
		hostname = f'{ext.subdomain}.{ext.domain}.{ext.suffix}'
	else:
		hostname = domain

	try:
		ipaddress.ip_address(hostname)
		type_ip = True
		ip = hostname
	except Exception:
		try:
			ip = socket.gethostbyname(hostname)
			print_formatted_result(f"IP Address: {str(ip)}")
		except Exception as e:
			print(f'\n{R}[-] {C}Unable to Get IP : {W}{str(e)}')
			sys.exit(1)

	start_time = datetime.datetime.now()

	# Initialize out_settings and respath with default values
	out_settings = {
		'format': 'None',
		'directory': None,
		'file': None
	}
	respath = None

	if output != 'None':
		fpath = usr_data
		ist = pytz.timezone('Asia/Kolkata')
		dt_now = str(datetime.datetime.now(ist).strftime('%d-%m-%Y_%H-%M-%S'))  # Changed : to - for Windows compatibility
		fname = f'{dt_now}_{hostname}.{output}'
		respath = f'{fpath}_{dt_now}_{hostname}'
		if not os.path.exists(respath):
			os.makedirs(respath)
		out_settings = {
			'format': output,
			'directory': respath,
			'file': fname
		}
		log_writer(f'OUTPUT = FORMAT: {output}, DIR: {respath}, FILENAME: {fname}')

	if full:
		log_writer('Starting full recon...')

		from modules.dns import dnsrec
		from modules.sslinfo import cert
		from modules.portscan import scan
		from modules.dirrec import hammer
		from modules.crawler import crawler
		from modules.headers import headers
		from modules.subdom import subdomains
		from modules.wayback import timetravel
		from modules.whois import whois_lookup

		headers(target, out_settings, data, print_formatted_result)
		cert(hostname, sslp, out_settings, data, print_formatted_result)
		whois_lookup(domain, domain_suffix, path_to_script, out_settings, data, print_formatted_result)
		dnsrec(domain, out_settings, data, print_formatted_result)
		if not type_ip:
			subdomains(domain, tout, out_settings, data, conf_path, print_formatted_result)
		scan(ip, out_settings, data, pscan_threads, print_formatted_result)
		crawler(target, out_settings, data, print_formatted_result)
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, out_settings, data, filext, print_formatted_result)
		timetravel(target, data, out_settings, print_formatted_result)

	if headinfo:
		from modules.headers import headers
		log_writer('Starting header enum...')
		headers(target, out_settings, data, print_formatted_result)

	if sslinfo:
		from modules.sslinfo import cert
		log_writer('Starting SSL enum...')
		cert(hostname, sslp, out_settings, data, print_formatted_result)

	if whois:
		from modules.whois import whois_lookup
		log_writer('Starting whois enum...')
		whois_lookup(domain, domain_suffix, path_to_script, out_settings, data, print_formatted_result)

	if crawl:
		from modules.crawler import crawler
		log_writer('Starting crawler...')
		crawler(target, out_settings, data, print_formatted_result)

	if dns:
		from modules.dns import dnsrec
		log_writer('Starting DNS enum...')
		dnsrec(domain, out_settings, data, print_formatted_result)

	if subd and not type_ip:
		from modules.subdom import subdomains
		log_writer('Starting subdomain enum...')
		subdomains(domain, tout, out_settings, data, conf_path, print_formatted_result)

	elif subd and type_ip:
		print_formatted_result("Sub-Domain Enumeration is Not Supported for IP Addresses")
		log_writer('Sub-Domain Enumeration is Not Supported for IP Addresses, exiting')
		sys.exit(1)

	if wback:
		from modules.wayback import timetravel
		log_writer('Starting wayback enum...')
		timetravel(hostname, data, out_settings, print_formatted_result)

	if pscan:
		from modules.portscan import scan
		log_writer('Starting port scan...')
		scan(ip, out_settings, data, pscan_threads, print_formatted_result)

	if dirrec:
		from modules.dirrec import hammer
		log_writer('Starting dir enum...')
		hammer(target, threads, tout, wdlist, redir, sslv, dserv, out_settings, data, filext, print_formatted_result)

	if not any([full, headinfo, sslinfo, whois, crawl, dns, subd, wback, pscan, dirrec]):
		print_formatted_result("Error: At least One Argument is Required with URL")
		log_writer('At least One Argument is Required with URL, exiting')
		output = 'None'
		sys.exit(1)

	end_time = datetime.datetime.now() - start_time
	data['Reconnaissance Completion Time'] = str(end_time)
	print_formatted_result(f"Reconnaissance completed in: {str(end_time)}")
	if respath:
		data['Results Exported To'] = respath
		print_formatted_result(f"Results exported to: {respath}")
		log_writer(f'Exported to {respath}')
	log_writer(f'{"-" * 30}')
	sys.exit()
except KeyboardInterrupt:
	print(f'{R}[-] {C}Keyboard Interrupt.{W}\n')
	log_writer('Keyboard interrupt, exiting')
	log_writer(f'{"-" * 30}')
	sys.exit(130)