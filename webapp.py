#!/usr/bin/env python3

import os
import sys
import json
import uuid
import time
import threading
import pytz
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file, url_for, make_response
from werkzeug.utils import secure_filename

# Custom JSON encoder to handle non-serializable objects
class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        # Handle datetime objects
        if isinstance(o, datetime):
            return o.isoformat()
        # Handle Version objects and other non-serializable objects
        return str(o)

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import settings as config

# We need to avoid importing the CLI argument parser from reconboss.py
# So we'll import the specific functions we need directly from modules
import tldextract
import socket

# Import for PDF generation
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

app = Flask(__name__)
app.secret_key = 'reconboss_secret_key_2025'

# Add CSP headers to all responses
@app.after_request
def after_request(response):
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdnjs.cloudflare.com; "
        "connect-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none';"
    )
    return response

# In-memory storage for scan tasks (in production, use a database)
scan_tasks = {}
scan_results = {}

# Directory for storing web results
WEB_RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'web_results')
if not os.path.exists(WEB_RESULTS_DIR):
    os.makedirs(WEB_RESULTS_DIR)

def run_scan_task(task_id, target_url, options):
    """Run the reconnaissance scan in a background thread"""
    try:
        scan_tasks[task_id]['status'] = 'running'
        scan_tasks[task_id]['start_time'] = time.time()
        
        # Import modules dynamically based on options
        data = {}
        # Get current time in IST
        ist = pytz.timezone('Asia/Kolkata')
        now = datetime.now(ist)
        scan_time = now.strftime('%d-%m-%Y %H:%M:%S IST')
        
        result_data = {
            'target': target_url,
            'scan_time': scan_time,
            'modules': {},
            'headers_info': {},
            'ssl_details': {}
        }
        
        # Parse target to get hostname
        ext = tldextract.extract(target_url)
        domain = ext.registered_domain if ext.registered_domain else ext.domain
        hostname = f'{ext.subdomain}.{ext.domain}.{ext.suffix}' if ext.subdomain else domain
        
        # Get IP address
        try:
            ip = socket.gethostbyname(hostname)
            result_data['ip_address'] = ip
        except:
            result_data['ip_address'] = 'Not available'
        
        # Prepare output settings
        out_settings = {
            'format': 'txt',
            'directory': os.path.join(WEB_RESULTS_DIR, task_id),
            'file': f'{task_id}_results.txt'
        }
        
        if not os.path.exists(out_settings['directory']):
            os.makedirs(out_settings['directory'])
        
        # Define a simple print function for web output that matches the signature of print_formatted_result
        def web_print(message, data_dict=None, **kwargs):
            # For web interface, we just collect the data
            # Ignore additional parameters like end and flush
            pass
        
        # Run selected modules
        if options.get('headers'):
            from modules.headers import headers
            headers(target_url, out_settings, data, web_print)
            # Parse headers for enhanced display
            headers_file = os.path.join(out_settings['directory'], 'headers.txt')
            if os.path.exists(headers_file):
                with open(headers_file, 'r', encoding='utf-8', errors='ignore') as f:
                    headers_content = f.read()
                    result_data['modules']['headers'] = headers_content.split('\n')
                    # Extract key headers for enhanced display
                    try:
                        headers_dict = {}
                        for line in headers_content.split('\n'):
                            if ':' in line:
                                key, value = line.split(':', 1)
                                headers_dict[key.strip()] = value.strip()
                        result_data['headers_info'] = headers_dict
                    except:
                        pass
        
        if options.get('sslinfo'):
            from modules.sslinfo import cert
            cert(hostname, config.ssl_port, out_settings, data, web_print)
            # Parse SSL info for enhanced display
            ssl_file = os.path.join(out_settings['directory'], 'ssl.txt')
            if os.path.exists(ssl_file):
                with open(ssl_file, 'r', encoding='utf-8', errors='ignore') as f:
                    ssl_content = f.read()
                    result_data['modules']['ssl_info'] = ssl_content.split('\n')
                    # Extract key SSL details for enhanced display
                    try:
                        ssl_details = {}
                        current_section = None
                        subject_info = []
                        issuer_info = []
                        san_info = []
                        
                        for line in ssl_content.split('\n'):
                            line = line.strip()
                            if not line:
                                continue
                                
                            if line.startswith('[+]'):
                                current_section = line[4:].strip()
                                if 'Subject' in current_section:
                                    subject_info = []
                                elif 'Issuer' in current_section:
                                    issuer_info = []
                                elif 'Subject Alternative Name' in current_section:
                                    san_info = []
                            elif ':' in line:
                                key, value = line.split(':', 1)
                                key = key.strip()
                                value = value.strip()
                                
                                if current_section and 'Subject' in current_section and 'Subject Alternative Name' not in current_section:
                                    subject_info.append(f"{key}: {value}")
                                elif current_section and 'Issuer' in current_section:
                                    issuer_info.append(f"{key}: {value}")
                                elif current_section and 'Subject Alternative Name' in current_section:
                                    san_info.append(value)
                            elif line and current_section:
                                if current_section and 'Subject' in current_section and 'Subject Alternative Name' not in current_section:
                                    subject_info.append(line)
                                elif current_section and 'Issuer' in current_section:
                                    issuer_info.append(line)
                                elif current_section and 'Subject Alternative Name' in current_section:
                                    san_info.append(line)
                        
                        # Add parsed information to ssl_details
                        if subject_info:
                            ssl_details['subject'] = subject_info
                        if issuer_info:
                            ssl_details['issuer'] = issuer_info
                        if san_info:
                            ssl_details['subjectAltName'] = san_info
                            
                        result_data['ssl_details'] = ssl_details
                    except Exception as e:
                        # If parsing fails, we'll display raw content
                        pass
        
        if options.get('whois'):
            from modules.whois import whois_lookup
            ext = tldextract.extract(target_url)
            domain = ext.registered_domain if ext.registered_domain else ext.domain
            whois_lookup(domain, ext.suffix, os.path.dirname(os.path.abspath(__file__)), out_settings, data, web_print)
            whois_file = os.path.join(out_settings['directory'], 'whois.txt')
            if os.path.exists(whois_file):
                with open(whois_file, 'r', encoding='utf-8', errors='ignore') as f:
                    result_data['modules']['whois'] = f.read().split('\n')
        
        if options.get('dns'):
            from modules.dns import dnsrec
            dnsrec(domain, out_settings, data, web_print)
            dns_file = os.path.join(out_settings['directory'], 'dns.txt')
            if os.path.exists(dns_file):
                with open(dns_file, 'r', encoding='utf-8', errors='ignore') as f:
                    result_data['modules']['dns'] = f.read().split('\n')
        
        if options.get('sub'):
            from modules.subdom import subdomains
            subdomains(domain, config.timeout, out_settings, data, config.conf_path, web_print)
            subdomains_file = os.path.join(out_settings['directory'], 'subdomains.txt')
            if os.path.exists(subdomains_file):
                with open(subdomains_file, 'r', encoding='utf-8', errors='ignore') as f:
                    result_data['modules']['subdomains'] = f.read().split('\n')
        
        if options.get('ps'):
            from modules.portscan import scan
            scan(result_data['ip_address'], out_settings, data, config.port_scan_th, web_print)
            portscan_file = os.path.join(out_settings['directory'], 'ports.txt')
            if os.path.exists(portscan_file):
                with open(portscan_file, 'r', encoding='utf-8', errors='ignore') as f:
                    result_data['modules']['portscan'] = f.read().split('\n')
        
        if options.get('crawl'):
            from modules.crawler import crawler
            crawler(target_url, out_settings, data, web_print)
            crawler_file = os.path.join(out_settings['directory'], 'crawler.txt')
            if os.path.exists(crawler_file):
                with open(crawler_file, 'r', encoding='utf-8', errors='ignore') as f:
                    result_data['modules']['crawler'] = f.read().split('\n')
        
        if options.get('dir'):
            from modules.dirrec import hammer
            hammer(target_url, config.dir_enum_th, config.timeout, config.dir_enum_wlist, 
                   config.dir_enum_redirect, config.dir_enum_sslv, config.dir_enum_dns, 
                   out_settings, data, config.dir_enum_ext, web_print)
            dir_file = os.path.join(out_settings['directory'], 'dirs.txt')
            if os.path.exists(dir_file):
                with open(dir_file, 'r', encoding='utf-8', errors='ignore') as f:
                    result_data['modules']['directory'] = f.read().split('\n')
        
        if options.get('wayback'):
            from modules.wayback import timetravel
            timetravel(target_url, data, out_settings, web_print)
            wayback_file = os.path.join(out_settings['directory'], 'wayback.txt')
            if os.path.exists(wayback_file):
                with open(wayback_file, 'r', encoding='utf-8', errors='ignore') as f:
                    result_data['modules']['wayback'] = f.read().split('\n')
        
        # Save results
        scan_results[task_id] = result_data
        
        # Save structured results to JSON file
        results_json_path = os.path.join(out_settings['directory'], 'formatted_results.json')
        with open(results_json_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, cls=CustomJSONEncoder)
        
        # Save raw output
        raw_output_path = os.path.join(out_settings['directory'], 'results.json')
        with open(raw_output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, cls=CustomJSONEncoder)
        
        scan_tasks[task_id]['status'] = 'completed'
        scan_tasks[task_id]['elapsed_time'] = time.time() - scan_tasks[task_id]['start_time']
        scan_tasks[task_id]['exported_path'] = out_settings['directory']
        
    except Exception as e:
        scan_tasks[task_id]['status'] = 'error'
        scan_tasks[task_id]['error'] = str(e)
        # Save error to file
        error_path = os.path.join(WEB_RESULTS_DIR, task_id, 'errors.txt')
        with open(error_path, 'w', encoding='utf-8') as f:
            f.write(str(e))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    try:
        target_url = request.form.get('target_url')
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Add protocol if missing
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'https://' + target_url
        
        # Remove trailing slash
        if target_url.endswith('/'):
            target_url = target_url[:-1]
        
        # Get scan options
        options = {
            'headers': request.form.get('headers') == 'on',
            'sslinfo': request.form.get('sslinfo') == 'on',
            'whois': request.form.get('whois') == 'on',
            'crawl': request.form.get('crawl') == 'on',
            'dns': request.form.get('dns') == 'on',
            'sub': request.form.get('sub') == 'on',
            'dir': request.form.get('dir') == 'on',
            'wayback': request.form.get('wayback') == 'on',
            'ps': request.form.get('ps') == 'on',
            'full': request.form.get('full') == 'on'
        }
        
        # If full scan is selected, enable all modules
        if options['full']:
            for key in options:
                if key != 'full':
                    options[key] = True
        
        # Create a unique task ID
        task_id = str(uuid.uuid4())
        
        # Initialize task
        scan_tasks[task_id] = {
            'status': 'initialized',
            'target_url': target_url,
            'options': options,
            'start_time': None,
            'elapsed_time': None
        }
        
        # Start scan in background thread
        thread = threading.Thread(target=run_scan_task, args=(task_id, target_url, options))
        thread.daemon = True
        thread.start()
        
        return jsonify({'task_id': task_id})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/status/<task_id>')
def status(task_id):
    if task_id not in scan_tasks:
        return jsonify({'error': 'Task not found'}), 404
    
    task = scan_tasks[task_id]
    response = {
        'status': task['status'],
        'target_url': task.get('target_url', ''),
        'elapsed_time': task.get('elapsed_time', 0)
    }
    
    if 'error' in task:
        response['error'] = task['error']
    
    return jsonify(response)

@app.route('/results/<task_id>')
def results(task_id):
    if task_id not in scan_tasks:
        return 'Task not found', 404
    
    task = scan_tasks[task_id]
    if task['status'] != 'completed':
        return 'Scan not completed yet', 400
    
    # Try to get structured results first
    results_dir = os.path.join(WEB_RESULTS_DIR, task_id)
    formatted_results_path = os.path.join(results_dir, 'formatted_results.json')
    
    if os.path.exists(formatted_results_path):
        with open(formatted_results_path, 'r', encoding='utf-8') as f:
            result_data = json.load(f)
        return render_template('results.html', task_id=task_id, result_data=result_data, task=task)
    
    # Fallback to raw results
    results_path = os.path.join(results_dir, 'results.json')
    if os.path.exists(results_path):
        with open(results_path, 'r', encoding='utf-8') as f:
            result_data = json.load(f)
        return render_template('results.html', task_id=task_id, result_data=result_data, task=task)
    
    return 'No results found', 404

@app.route('/results_json/<task_id>')
def results_json(task_id):
    if task_id not in scan_results:
        # Try to load from file
        results_dir = os.path.join(WEB_RESULTS_DIR, task_id)
        formatted_results_path = os.path.join(results_dir, 'formatted_results.json')
        
        if os.path.exists(formatted_results_path):
            with open(formatted_results_path, 'r', encoding='utf-8') as f:
                result_data = json.load(f)
                scan_results[task_id] = result_data
        else:
            return jsonify({'error': 'Results not found'}), 404
    
    return jsonify(scan_results[task_id])

@app.route('/download/<task_id>')
def download_results(task_id):
    if task_id not in scan_tasks:
        return 'Task not found', 404
    
    results_dir = os.path.join(WEB_RESULTS_DIR, task_id)
    txt_file = os.path.join(results_dir, f'{task_id}_results.txt')
    
    if os.path.exists(txt_file):
        return send_file(txt_file, as_attachment=True, download_name=f'reconboss_results_{task_id}.txt')
    
    # Fallback to any txt file in the directory
    for file in os.listdir(results_dir):
        if file.endswith('.txt'):
            return send_file(os.path.join(results_dir, file), as_attachment=True, download_name=file)
    
    return 'No results file found', 404

@app.route('/download_json/<task_id>')
def download_json_results(task_id):
    if task_id not in scan_tasks:
        return 'Task not found', 404
    
    results_dir = os.path.join(WEB_RESULTS_DIR, task_id)
    json_file = os.path.join(results_dir, 'formatted_results.json')
    
    if os.path.exists(json_file):
        return send_file(json_file, as_attachment=True, download_name=f'reconboss_results_{task_id}.json')
    
    return 'No JSON results file found', 404

def generate_pdf_report(task_id, result_data):
    """Generate a PDF report from scan results"""
    # Create PDF filename
    pdf_filename = f'reconboss_results_{task_id}.pdf'
    pdf_path = os.path.join(WEB_RESULTS_DIR, task_id, pdf_filename)
    
    # Create the PDF document
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=1  # Center alignment
    )
    title = Paragraph("ReconBoss Scan Report", title_style)
    story.append(title)
    
    # Scan details
    details_style = ParagraphStyle(
        'Details',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=12
    )
    
    # Target information
    story.append(Paragraph(f"<b>Target:</b> {result_data.get('target', 'N/A')}", details_style))
    story.append(Paragraph(f"<b>Scan Time:</b> {result_data.get('scan_time', 'N/A')}", details_style))
    story.append(Paragraph(f"<b>Task ID:</b> {task_id}", details_style))
    
    if 'ip_address' in result_data:
        story.append(Paragraph(f"<b>IP Address:</b> {result_data['ip_address']}", details_style))
    
    story.append(Spacer(1, 20))
    
    # Headers information
    if 'headers_info' in result_data and result_data['headers_info']:
        story.append(Paragraph("<b>Headers Information</b>", styles['Heading2']))
        headers_data = [[key, value] for key, value in result_data['headers_info'].items()]
        headers_table = Table(headers_data)
        headers_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(headers_table)
        story.append(Spacer(1, 20))
    
    # SSL information
    if 'ssl_details' in result_data and result_data['ssl_details']:
        story.append(Paragraph("<b>SSL Information</b>", styles['Heading2']))
        ssl_data = []
        for key, value in result_data['ssl_details'].items():
            if isinstance(value, list):
                # For lists, join items with commas
                ssl_data.append([key, ', '.join(map(str, value))])
            else:
                ssl_data.append([key, str(value)])
        
        if ssl_data:
            ssl_table = Table(ssl_data)
            ssl_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(ssl_table)
            story.append(Spacer(1, 20))
    
    # Modules results
    if 'modules' in result_data and result_data['modules']:
        for module_name, module_content in result_data['modules'].items():
            story.append(Paragraph(f"<b>{module_name.title()} Results</b>", styles['Heading2']))
            
            if isinstance(module_content, list):
                # Convert list to string
                content_text = '\n'.join(module_content)
            else:
                content_text = str(module_content)
                
            # Add content as a paragraph with monospace font
            content_style = ParagraphStyle(
                'Code',
                parent=styles['Normal'],
                fontName='Courier',
                fontSize=8,
                leading=10
            )
            story.append(Paragraph(content_text.replace('\n', '<br/>'), content_style))
            story.append(Spacer(1, 20))
    
    # Build PDF
    doc.build(story)
    return pdf_path

@app.route('/download_pdf/<task_id>')
def download_pdf_results(task_id):
    if task_id not in scan_tasks:
        return 'Task not found', 404
    
    # Load results data
    results_dir = os.path.join(WEB_RESULTS_DIR, task_id)
    formatted_results_path = os.path.join(results_dir, 'formatted_results.json')
    
    if not os.path.exists(formatted_results_path):
        return 'No results found', 404
    
    with open(formatted_results_path, 'r', encoding='utf-8') as f:
        result_data = json.load(f)
    
    # Generate PDF if it doesn't exist
    pdf_filename = f'reconboss_results_{task_id}.pdf'
    pdf_path = os.path.join(results_dir, pdf_filename)
    
    if not os.path.exists(pdf_path):
        try:
            pdf_path = generate_pdf_report(task_id, result_data)
        except Exception as e:
            return f'Error generating PDF: {str(e)}', 500
    
    return send_file(pdf_path, as_attachment=True, download_name=pdf_filename)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)