#!/usr/bin/env python3

import ssl
import socket
import pytz
from datetime import datetime
from modules.export import export
from modules.write_log import log_writer
from cryptography import x509
from cryptography.hazmat.backends import default_backend

R = '\033[31m'  # red
G = '\033[32m'  # green
C = '\033[36m'  # cyan
W = '\033[0m'   # white
Y = '\033[33m'  # yellow


def convert_to_ist(dt):
    """Convert a datetime to IST format"""
    # Convert to IST timezone
    ist = pytz.timezone('Asia/Kolkata')
    if dt.tzinfo is None:
        # Assume the datetime is in UTC and convert to IST
        utc = pytz.UTC
        dt = utc.localize(dt)
    dt_ist = dt.astimezone(ist)
    return dt_ist.strftime("%b %d %H:%M:%S %Y IST")


def cert(hostname, sslp, output, data, print_formatted_result_func):
	result = {}
	presence = False
	print_formatted_result_func('Initiating SSL Certificate Information Scan', {})

	port_test = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	port_test.settimeout(5)
	try:
		port_test.connect((hostname, sslp))
		port_test.close()
		presence = True
	except Exception:
		port_test.close()
		print_formatted_result_func('SSL is not Present on Target URL...Skipping...')
		result.update({'Error': 'SSL is not Present on Target URL'})
		log_writer('[sslinfo] SSL is not Present on Target URL...Skipping...')

	def unpack(nested_tuple, pair):
		for item in nested_tuple:
			if isinstance(item, tuple):
				if len(item) == 2:
					pair[item[0]] = item[1]
				else:
					unpack(item, pair)
			else:
				pair[nested_tuple.index(item)] = item

	def process_cert(info):
		pair = {}
		for key, val in info.items():
			if isinstance(val, tuple):
				print_formatted_result_func(f"{key}")
				unpack(val, pair)
				for sub_key, sub_val in pair.items():
					# Handle Unicode characters that might cause encoding issues
					try:
						print_formatted_result_func(f"  {sub_key}: {sub_val}")
					except UnicodeEncodeError:
						# If there's a Unicode encoding issue, convert to ASCII
						safe_sub_val = sub_val.encode('ascii', 'ignore').decode('ascii')
						print_formatted_result_func(f"  {sub_key}: {safe_sub_val}")
					result.update({f'{key}-{sub_key}': sub_val})
				pair.clear()
			elif isinstance(val, dict):
				print_formatted_result_func(f"{key}")
				for sub_key, sub_val in val.items():
					# Handle Unicode characters that might cause encoding issues
					try:
						print_formatted_result_func(f"  {sub_key}: {sub_val}")
					except UnicodeEncodeError:
						# If there's a Unicode encoding issue, convert to ASCII
						safe_sub_val = sub_val.encode('ascii', 'ignore').decode('ascii')
						print_formatted_result_func(f"  {sub_key}: {safe_sub_val}")
					result.update({f'{key}-{sub_key}': sub_val})
			elif isinstance(val, list):
				print_formatted_result_func(f"{key}")
				for sub_val in val:
					# Handle Unicode characters that might cause encoding issues
					try:
						print_formatted_result_func(f"  {sub_val}")
					except UnicodeEncodeError:
						# If there's a Unicode encoding issue, convert to ASCII
						safe_sub_val = sub_val.encode('ascii', 'ignore').decode('ascii')
						print_formatted_result_func(f"  {safe_sub_val}")
					result.update({f'{key}-{val.index(sub_val)}': sub_val})
			else:
				# Handle Unicode characters that might cause encoding issues
				try:
					print_formatted_result_func(f"{key}: {val}")
				except UnicodeEncodeError:
					# If there's a Unicode encoding issue, convert to ASCII
					safe_val = val.encode('ascii', 'ignore').decode('ascii')
					print_formatted_result_func(f"{key}: {safe_val}")
				result.update({key: val})

	if presence:
		ctx = ssl.create_default_context()
		ctx.check_hostname = False
		ctx.verify_mode = ssl.CERT_NONE
		sock = socket.socket()
		sock.settimeout(5)
		ssl_conn = ctx.wrap_socket(sock, server_hostname=hostname)
		ssl_conn.connect((hostname, sslp))
		x509_cert = ssl_conn.getpeercert(binary_form=True)
		decoded_cert = x509.load_der_x509_certificate(x509_cert, default_backend())

		subject_dict = {}
		issuer_dict = {}

		def name_to_dict(attribute):
			attr_name = str(attribute.oid._name)
			attr_value = str(attribute.value) if attribute.value is not None else ''
			return attr_name, attr_value

		for attribute in decoded_cert.subject:
			name, value = name_to_dict(attribute)
			subject_dict[name] = value

		for attribute in decoded_cert.issuer:
			name, value = name_to_dict(attribute)
			issuer_dict[name] = value

		cert_dict = {
			'protocol': ssl_conn.version(),
			'cipher': str(ssl_conn.cipher()),
			'subject': subject_dict,
			'issuer': issuer_dict,
			'version': str(decoded_cert.version),
			'serialNumber': str(decoded_cert.serial_number),
			'notBefore': convert_to_ist(decoded_cert.not_valid_before_utc),
			'notAfter': convert_to_ist(decoded_cert.not_valid_after_utc),
		}

		extensions = decoded_cert.extensions
		for ext in extensions:
			if ext.oid != x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
				continue
			san_entries = ext.value
			subject_alt_names = []
			for entry in san_entries:
				if isinstance(entry, x509.DNSName):
					subject_alt_names.append(entry.value)
			cert_dict['subjectAltName'] = subject_alt_names

		process_cert(cert_dict)
	result.update({'exported': False})

	if output:
		fname = f'{output["directory"]}/ssl.{output["format"]}'
		output['file'] = fname
		data['module-SSL Certificate Information'] = result
		export(output, data)
	log_writer('[sslinfo] Completed')