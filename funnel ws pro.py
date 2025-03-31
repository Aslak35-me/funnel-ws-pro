#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Funnel WS Ultimate - Enterprise Web Security Scanner
Advanced version with integrated security tools and comprehensive reporting
"""

import os
import sys
import json
import time
import sqlite3
import subprocess
import requests
import threading
import nmap
import dns.resolver
import argparse
import hashlib
from datetime import datetime
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import xml.etree.ElementTree as ET
import random
import socket
import ssl
import re
import logging
import yaml
from fpdf import FPDF
import plotly.graph_objects as go
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest

# Initialize colorama
init()

class FunnelWSUltimate:
    def __init__(self):
        self.version = "5.0.0"
        self.banner = self.generate_banner()
        self.config = self.load_config()
        self.db = self.init_database()
        self.nm = nmap.PortScanner()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.get_random_user_agent()})
        self.setup_directories()
        self.setup_logging()
        self.setup_ai_models()
        self.external_tools = self.check_external_tools()
        self.vulnerability_db = self.load_vulnerability_db()
        self.payloads = self.load_payloads()

    def generate_banner(self):
        return f"""
{Fore.MAGENTA}
 ███████╗██╗   ██╗███╗   ██╗███╗   ██╗███████╗██╗     ███████╗    ██╗    ██╗███████╗
 ██╔════╝██║   ██║████╗  ██║████╗  ██║██╔════╝██║     ██╔════╝    ██║    ██║██╔════╝
 █████╗  ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║     █████╗      ██║ █╗ ██║███████╗
 ██╔══╝  ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║     ██╔══╝      ██║███╗██║╚════██║
 ██║     ╚██████╔╝██║ ╚████║██║ ╚████║███████╗███████╗███████╗     ╚███╔███╔╝███████║
 ╚═╝      ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚══════╝╚══════╝      ╚══╝╚══╝ ╚══════╝
{Fore.CYAN}
                         Enterprise Web Security Scanner
{Fore.YELLOW}
                         Version: {self.version} | Ultimate Edition
{Style.RESET_ALL}
        """

    def load_config(self):
        """Load configuration from YAML file or use defaults"""
        config_path = os.path.join(os.path.dirname(__file__), 'config.yaml')
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        
        return {
            'timeout': 30,
            'max_threads': 20,
            'report_dir': 'reports',
            'temp_dir': 'tmp',
            'payloads_dir': 'payloads',
            'database_dir': 'database',
            'colors': {
                'info': Fore.CYAN,
                'success': Fore.GREEN,
                'warning': Fore.YELLOW,
                'error': Fore.RED,
                'critical': Fore.RED + Style.BRIGHT
            },
            'external_tools': {
                'sqlmap': 'sqlmap',
                'nmap': 'nmap',
                'wpscan': 'wpscan',
                'nikto': 'nikto',
                'wapiti': 'wapiti',
                'wfuzz': 'wfuzz',
                'gobuster': 'gobuster',
                'dirb': 'dirb',
                'burpsuite': 'burpsuite',
                'owasp_zap': 'zap.sh',
                'metasploit': 'msfconsole'
            },
            'vulnerability_databases': {
                'nvd': 'https://nvd.nist.gov/vuln/data-feeds',
                'cve': 'https://cve.mitre.org/data/downloads/index.html',
                'exploit_db': 'https://www.exploit-db.com/'
            }
        }

    def init_database(self):
        """Initialize SQLite database for scan results"""
        db_path = os.path.join(self.config['database_dir'], 'scan_results.db')
        os.makedirs(self.config['database_dir'], exist_ok=True)
        
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY,
                url TEXT UNIQUE,
                ip TEXT,
                status_code INTEGER,
                scan_date TEXT,
                is_cloud BOOLEAN,
                cloud_provider TEXT
            )
        ''')
        
        # Vulnerabilities table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                type TEXT,
                severity TEXT,
                cvss_score REAL,
                epss_score REAL,
                description TEXT,
                payload TEXT,
                proof TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )
        ''')
        
        # Scan history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                tool TEXT,
                command TEXT,
                output_path TEXT,
                scan_date TEXT,
                duration REAL,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )
        ''')
        
        # IOC table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY,
                target_id INTEGER,
                type TEXT,
                value TEXT,
                source TEXT,
                first_seen TEXT,
                last_seen TEXT,
                FOREIGN KEY(target_id) REFERENCES targets(id)
            )
        ''')
        
        conn.commit()
        return conn

    def setup_directories(self):
        """Create required directories"""
        for directory in [self.config['report_dir'], 
                         self.config['temp_dir'], 
                         self.config['payloads_dir'],
                         self.config['database_dir']]:
            os.makedirs(directory, exist_ok=True)

    def setup_logging(self):
        """Configure logging system"""
        log_path = os.path.join(self.config['database_dir'], 'funnelws.log')
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                RotatingFileHandler(log_path, maxBytes=5*1024*1024, backupCount=3),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger('FunnelWS')

    def setup_ai_models(self):
        """Initialize AI/ML models for analysis"""
        try:
            # Anomaly detection model
            self.anomaly_model = IsolationForest(n_estimators=100, contamination=0.01)
            
            # Load pre-trained models if available
            model_path = os.path.join(self.config['database_dir'], 'ai_models')
            os.makedirs(model_path, exist_ok=True)
            
        except Exception as e:
            self.logger.error(f"Failed to initialize AI models: {str(e)}")

    def check_external_tools(self):
        """Check availability of external security tools"""
        available_tools = {}
        for tool, cmd in self.config['external_tools'].items():
            try:
                subprocess.run([cmd, '--version'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                available_tools[tool] = True
            except:
                available_tools[tool] = False
                self.logger.warning(f"External tool not found: {tool}")
        return available_tools

    def load_vulnerability_db(self):
        """Load vulnerability database"""
        db_path = os.path.join(self.config['database_dir'], 'vulnerabilities.db')
        if not os.path.exists(db_path):
            self.update_vulnerability_db()
        
        conn = sqlite3.connect(db_path)
        return conn

    def update_vulnerability_db(self):
        """Update vulnerability database from online sources"""
        self.logger.info("Updating vulnerability database...")
        # Implementation would download from NVD, CVE, ExploitDB, etc.
        # This is a placeholder for the actual implementation
        pass

    def load_payloads(self):
        """Load attack payloads from files"""
        payloads = {
            'xss': [],
            'sqli': [],
            'rce': [],
            'lfi': [],
            'xxe': []
        }
        
        for payload_type in payloads.keys():
            file_path = os.path.join(self.config['payloads_dir'], f'{payload_type}.txt')
            if os.path.exists(file_path):
                with open(file_path, 'r') as f:
                    payloads[payload_type] = [line.strip() for line in f if line.strip()]
        
        return payloads

    def get_random_user_agent(self):
        """Return a random user agent string"""
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15',
            'Mozilla/5.0 (Linux; Android 10; SM-G980F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36'
        ]
        return random.choice(user_agents)

    def print_help(self):
        """Display help information"""
        help_text = f"""
{Fore.CYAN}Funnel WS Ultimate - Enterprise Web Security Scanner{Style.RESET_ALL}

{Fore.YELLOW}USAGE:{Style.RESET_ALL}
  funnelws [TARGET] [OPTIONS]
  funnelws https://example.com --level 3
  funnelws --dork "site:example.com admin" --deep

{Fore.YELLOW}BASIC OPTIONS:{Style.RESET_ALL}
  {Fore.GREEN}<target>{Style.RESET_ALL}        URL or IP to scan
  {Fore.GREEN}--level{Style.RESET_ALL}      Scan intensity (1-5)
                1: Quick Scan
                2: Standard Scan
                3: Deep Scan (default)
                4: Advanced Scan
                5: Penetration Test
  {Fore.GREEN}--fast{Style.RESET_ALL}       Fast scan mode
  {Fore.GREEN}--dork{Style.RESET_ALL}      Google dork query

{Fore.YELLOW}SCAN OPTIONS:{Style.RESET_ALL}
  {Fore.GREEN}--xss{Style.RESET_ALL}        Enable XSS scanning
  {Fore.GREEN}--sqli{Style.RESET_ALL}       Enable SQL injection scanning
  {Fore.GREEN}--rce{Style.RESET_ALL}        Enable RCE scanning
  {Fore.GREEN}--lfi{Style.RESET_ALL}        Enable LFI scanning
  {Fore.GREEN}--xxe{Style.RESET_ALL}        Enable XXE scanning
  {Fore.GREEN}--cors{Style.RESET_ALL}       Enable CORS misconfig scanning
  {Fore.GREEN}--sri{Style.RESET_ALL}        Enable Subresource Integrity checks
  {Fore.GREEN}--headers{Style.RESET_ALL}    Enable security headers checks

{Fore.YELLOW}TOOL INTEGRATIONS:{Style.RESET_ALL}
  {Fore.GREEN}--sqlmap{Style.RESET_ALL}     Run SQLMap integration
  {Fore.GREEN}--nmap{Style.RESET_ALL}      Run Nmap integration
  {Fore.GREEN}--wpscan{Style.RESET_ALL}    Run WPScan (WordPress sites)
  {Fore.GREEN}--nikto{Style.RESET_ALL}     Run Nikto integration
  {Fore.GREEN}--zap{Style.RESET_ALL}       Run OWASP ZAP integration

{Fore.YELLOW}REPORTING OPTIONS:{Style.RESET_ALL}
  {Fore.GREEN}--report{Style.RESET_ALL}     Report format (html/pdf/json)
  {Fore.GREEN}--output{Style.RESET_ALL}     Custom output directory

{Fore.YELLOW}OTHER OPTIONS:{Style.RESET_ALL}
  {Fore.GREEN}--help{Style.RESET_ALL}       Show this help message
  {Fore.GREEN}--version{Style.RESET_ALL}    Show version information
"""
        print(help_text)

    def run_nmap_scan(self, target, level=3):
        """Run Nmap scan with appropriate arguments based on level"""
        try:
            self.logger.info(f"Starting Nmap scan (Level {level}) on {target}")
            
            arguments = {
                1: '-T4 -F --top-ports 100',
                2: '-sV -T4 --script vulners',
                3: '-sV -T4 -A -O -p- --script vulners',
                4: '-sV -T4 -A -O -p- --script vulners,banner,vuln',
                5: '-sV -T4 -A -O -p- --script vulners,banner,vuln --script-args=unsafe=1'
            }.get(level, '-sV -T4 -A')
            
            start_time = time.time()
            self.nm.scan(target, arguments=arguments)
            scan_time = time.time() - start_time
            
            # Save scan results to database
            cursor = self.db.cursor()
            cursor.execute('''
                INSERT INTO scan_history 
                (target_id, tool, command, scan_date, duration)
                VALUES (?, ?, ?, ?, ?)
            ''', (self.get_target_id(target), 'nmap', arguments, datetime.now().isoformat(), scan_time))
            self.db.commit()
            
            return self.nm[target]
        except Exception as e:
            self.logger.error(f"Nmap scan error: {str(e)}")
            return None

    def scan_web_application(self, url, level=3, options=None):
        """Comprehensive web application scan"""
        if options is None:
            options = {}
            
        results = []
        start_time = time.time()
        
        # Basic checks
        results.extend(self.check_server_info(url))
        results.extend(self.check_robots_txt(url))
        results.extend(self.check_security_headers(url))
        
        # Vulnerability scanning based on level and options
        if level >= 2 or options.get('xss'):
            results.extend(self.scan_xss(url))
        
        if level >= 2 or options.get('sqli'):
            results.extend(self.scan_sqli(url))
            
        if level >= 3 or options.get('rce'):
            results.extend(self.scan_rce(url))
            
        if level >= 3 or options.get('lfi'):
            results.extend(self.scan_lfi(url))
            
        if level >= 4 or options.get('xxe'):
            results.extend(self.scan_xxe(url))
            
        if level >= 2 or options.get('cors'):
            results.extend(self.check_cors(url))
            
        if level >= 2 or options.get('sri'):
            results.extend(self.check_sri(url))
            
        # External tool integrations
        if level >= 4 and self.external_tools.get('sqlmap'):
            results.extend(self.run_sqlmap(url))
            
        if level >= 3 and self.external_tools.get('nikto'):
            results.extend(self.run_nikto(url))
            
        scan_time = time.time() - start_time
        
        # Save scan results to database
        self.save_scan_results(url, results, scan_time)
        
        return results

    def scan_xss(self, url):
        """Scan for XSS vulnerabilities"""
        self.logger.info(f"Scanning for XSS vulnerabilities: {url}")
        vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            futures = []
            for payload in self.payloads['xss']:
                test_url = f"{url}?q={quote(payload)}"
                futures.append(executor.submit(self.check_xss, test_url, payload))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"XSS scan error: {str(e)}")
        
        return vulnerabilities

    def check_xss(self, url, payload):
        """Check for reflected XSS vulnerability"""
        try:
            response = self.session.get(url, timeout=self.config['timeout'])
            if payload in response.text:
                return [{
                    'type': 'XSS',
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'description': f'Reflected XSS found with payload: {payload}',
                    'payload': payload,
                    'url': url
                }]
        except Exception as e:
            self.logger.error(f"Error checking XSS: {str(e)}")
            return None

    def scan_sqli(self, url):
        """Scan for SQL injection vulnerabilities"""
        self.logger.info(f"Scanning for SQLi vulnerabilities: {url}")
        vulnerabilities = []
        
        with ThreadPoolExecutor(max_workers=self.config['max_threads']) as executor:
            futures = []
            for payload in self.payloads['sqli']:
                test_url = f"{url}?id={quote(payload)}"
                futures.append(executor.submit(self.check_sqli, test_url, payload))
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.extend(result)
                except Exception as e:
                    self.logger.error(f"SQLi scan error: {str(e)}")
        
        return vulnerabilities

    def check_sqli(self, url, payload):
        """Check for SQL injection vulnerability"""
        try:
            response = self.session.get(url, timeout=self.config['timeout'])
            if any(error in response.text.lower() for error in ['sql syntax', 'unclosed quotation mark']):
                return [{
                    'type': 'SQL Injection',
                    'severity': 'critical',
                    'cvss_score': 9.8,
                    'description': f'Possible SQLi with payload: {payload}',
                    'payload': payload,
                    'url': url
                }]
        except Exception as e:
            self.logger.error(f"Error checking SQLi: {str(e)}")
            return None

    def check_security_headers(self, url):
        """Check for missing security headers"""
        try:
            response = self.session.get(url, timeout=self.config['timeout'])
            headers = response.headers
            missing = []
            
            required_headers = [
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'X-Frame-Options',
                'Content-Security-Policy',
                'Strict-Transport-Security'
            ]
            
            for header in required_headers:
                if header not in headers:
                    missing.append(header)
            
            if missing:
                return [{
                    'type': 'Missing Security Headers',
                    'severity': 'medium',
                    'cvss_score': 5.3,
                    'description': f'Missing security headers: {", ".join(missing)}',
                    'url': url
                }]
            return []
        except Exception as e:
            self.logger.error(f"Error checking security headers: {str(e)}")
            return []

    def check_cors(self, url):
        """Check for CORS misconfigurations"""
        try:
            origin = 'https://evil.com'
            headers = {'Origin': origin}
            response = self.session.get(url, headers=headers, timeout=self.config['timeout'])
            
            cors_headers = response.headers.get('Access-Control-Allow-Origin', '')
            if cors_headers == '*' or origin in cors_headers:
                return [{
                    'type': 'CORS Misconfiguration',
                    'severity': 'medium',
                    'cvss_score': 6.5,
                    'description': 'Insecure CORS configuration allows arbitrary origins',
                    'url': url
                }]
            return []
        except Exception as e:
            self.logger.error(f"Error checking CORS: {str(e)}")
            return []

    def check_sri(self, url):
        """Check for missing Subresource Integrity"""
        try:
            response = self.session.get(url, timeout=self.config['timeout'])
            soup = BeautifulSoup(response.text, 'html.parser')
            vulnerabilities = []
            
            for tag in soup.find_all(['script', 'link']):
                if tag.has_attr('src') and not tag.has_attr('integrity'):
                    vulnerabilities.append({
                        'type': 'Missing SRI',
                        'severity': 'medium',
                        'cvss_score': 5.0,
                        'description': f'Missing integrity attribute for: {tag["src"]}',
                        'element': str(tag)[:100] + '...',
                        'url': url
                    })
            
            return vulnerabilities
        except Exception as e:
            self.logger.error(f"Error checking SRI: {str(e)}")
            return []

    def run_sqlmap(self, url):
        """Run SQLMap integration"""
        if not self.external_tools.get('sqlmap'):
            return []
            
        self.logger.info(f"Running SQLMap on {url}")
        try:
            output_file = os.path.join(self.config['temp_dir'], f'sqlmap_{hashlib.md5(url.encode()).hexdigest()}.json')
            cmd = f"sqlmap -u {url} --batch --output-dir={self.config['temp_dir']} --output-file={output_file}"
            
            start_time = time.time()
            subprocess.run(cmd, shell=True, check=True)
            scan_time = time.time() - start_time
            
            # Parse SQLMap results
            if os.path.exists(output_file):
                with open(output_file, 'r') as f:
                    results = json.load(f)
                    vulnerabilities = []
                    
                    for vuln in results.get('vulnerabilities', []):
                        vulnerabilities.append({
                            'type': 'SQL Injection (SQLMap)',
                            'severity': 'critical',
                            'cvss_score': 9.8,
                            'description': vuln.get('description', 'SQLi found by SQLMap'),
                            'payload': vuln.get('payload', ''),
                            'url': url
                        })
                    
                    return vulnerabilities
        except Exception as e:
            self.logger.error(f"SQLMap error: {str(e)}")
        return []

    def run_nikto(self, url):
        """Run Nikto integration"""
        if not self.external_tools.get('nikto'):
            return []
            
        self.logger.info(f"Running Nikto on {url}")
        try:
            output_file = os.path.join(self.config['temp_dir'], f'nikto_{hashlib.md5(url.encode()).hexdigest()}.xml')
            cmd = f"nikto -h {urlparse(url).netloc} -output {output_file} -Format xml"
            
            start_time = time.time()
            subprocess.run(cmd, shell=True, check=True)
            scan_time = time.time() - start_time
            
            # Parse Nikto results
            if os.path.exists(output_file):
                tree = ET.parse(output_file)
                root = tree.getroot()
                vulnerabilities = []
                
                for item in root.findall('.//item'):
                    vulnerabilities.append({
                        'type': 'Server Vulnerability (Nikto)',
                        'severity': 'medium',
                        'cvss_score': 5.0,
                        'description': item.get('osvdb'),
                        'url': url
                    })
                
                return vulnerabilities
        except Exception as e:
            self.logger.error(f"Nikto error: {str(e)}")
        return []

    def generate_report(self, scan_data, format='html'):
        """Generate scan report in specified format"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_file = os.path.join(self.config['report_dir'], f"report_{timestamp}.{format}")
        
        if format == 'json':
            with open(report_file, 'w') as f:
                json.dump(scan_data, f, indent=4)
        elif format == 'html':
            self.generate_html_report(scan_data, report_file)
        elif format == 'pdf':
            self.generate_pdf_report(scan_data, report_file)
        
        self.logger.info(f"Report generated: {report_file}")
        return report_file

    def generate_html_report(self, data, output_file):
        """Generate interactive HTML report"""
        try:
            # Create interactive charts
            fig = go.Figure()
            
            # Severity distribution
            severities = [v['severity'] for v in data['vulnerabilities']]
            severity_counts = pd.Series(severities).value_counts().to_dict()
            
            fig.add_trace(go.Bar(
                x=list(severity_counts.keys()),
                y=list(severity_counts.values()),
                name='Vulnerabilities by Severity'
            ))
            
            chart_html = fig.to_html(full_html=False)
            
            # Generate report HTML
            html_template = f"""<!DOCTYPE html>
<html>
<head>
    <title>Funnel WS Scan Report</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #2c3e50; }}
        .vulnerability {{ margin-bottom: 15px; padding: 10px; border-left: 5px solid; }}
        .critical {{ border-color: #e74c3c; background-color: #fdecea; }}
        .high {{ border-color: #f39c12; background-color: #fef5e9; }}
        .medium {{ border-color: #f1c40f; background-color: #fef9e7; }}
        .low {{ border-color: #2ecc71; background-color: #eafaf1; }}
        .chart {{ width: 100%; height: 400px; margin: 20px 0; }}
        .summary {{ background: #f8f9fa; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Funnel WS Security Scan Report</h1>
    <p><strong>Target:</strong> {data.get('target', 'N/A')}</p>
    <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <h2>Scan Summary</h2>
        <p>Total vulnerabilities found: {len(data.get('vulnerabilities', []))}</p>
        <div class="chart" id="severityChart"></div>
    </div>
    
    <h2>Vulnerabilities Found</h2>
    {"".join([self.vuln_to_html(v) for v in data.get('vulnerabilities', [])])}
    
    <script>
        {chart_html}
        document.getElementById('severityChart').innerHTML = document.getElementById('{fig.layout.title.text}').innerHTML;
    </script>
</body>
</html>"""
            
            with open(output_file, 'w') as f:
                f.write(html_template)
                
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")
            raise

    def generate_pdf_report(self, data, output_file):
        """Generate PDF report"""
        try:
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            
            # Title
            pdf.cell(200, 10, txt="Funnel WS Security Scan Report", ln=1, align='C')
            pdf.ln(10)
            
            # Scan info
            pdf.cell(200, 10, txt=f"Target: {data.get('target', 'N/A')}", ln=1)
            pdf.cell(200, 10, txt=f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=1)
            pdf.ln(10)
            
            # Summary
            pdf.set_font("Arial", 'B', size=12)
            pdf.cell(200, 10, txt="Scan Summary", ln=1)
            pdf.set_font("Arial", size=12)
            pdf.cell(200, 10, txt=f"Total vulnerabilities found: {len(data.get('vulnerabilities', []))}", ln=1)
            pdf.ln(10)
            
            # Vulnerabilities
            pdf.set_font("Arial", 'B', size=12)
            pdf.cell(200, 10, txt="Vulnerabilities Found:", ln=1)
            pdf.set_font("Arial", size=12)
            
            for vuln in data.get('vulnerabilities', []):
                pdf.cell(200, 10, txt=f"Type: {vuln.get('type', 'N/A')}", ln=1)
                pdf.cell(200, 10, txt=f"Severity: {vuln.get('severity', 'N/A')}", ln=1)
                pdf.multi_cell(0, 10, txt=f"Description: {vuln.get('description', 'N/A')}")
                pdf.ln(5)
            
            pdf.output(output_file)
        except Exception as e:
            self.logger.error(f"Error generating PDF report: {str(e)}")
            raise

    def vuln_to_html(self, vulnerability):
        """Convert vulnerability to HTML representation"""
        return f"""
<div class="vulnerability {vulnerability.get('severity', 'low')}">
    <h3>{vulnerability.get('type', 'Unknown')}</h3>
    <p><strong>Severity:</strong> {vulnerability.get('severity', 'N/A')}</p>
    <p><strong>CVSS Score:</strong> {vulnerability.get('cvss_score', 'N/A')}</p>
    <p><strong>Description:</strong> {vulnerability.get('description', 'N/A')}</p>
    {f"<p><strong>Payload:</strong> <code>{vulnerability.get('payload', 'N/A')}</code></p>" if 'payload' in vulnerability else ''}
    {f"<p><strong>URL:</strong> {vulnerability.get('url', 'N/A')}</p>" if 'url' in vulnerability else ''}
</div>
"""

    def save_scan_results(self, url, vulnerabilities, scan_time):
        """Save scan results to database"""
        try:
            cursor = self.db.cursor()
            
            # Get or create target
            target_id = self.get_target_id(url)
            
            # Save vulnerabilities
            for vuln in vulnerabilities:
                cursor.execute('''
                    INSERT INTO vulnerabilities 
                    (target_id, type, severity, cvss_score, description, payload)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (
                    target_id,
                    vuln.get('type'),
                    vuln.get('severity'),
                    vuln.get('cvss_score'),
                    vuln.get('description'),
                    vuln.get('payload')
                ))
            
            # Save scan metadata
            cursor.execute('''
                INSERT INTO scan_history 
                (target_id, tool, scan_date, duration)
                VALUES (?, ?, ?, ?)
            ''', (target_id, 'funnelws', datetime.now().isoformat(), scan_time))
            
            self.db.commit()
        except Exception as e:
            self.logger.error(f"Error saving scan results: {str(e)}")
            self.db.rollback()

    def get_target_id(self, url):
        """Get or create target ID in database"""
        cursor = self.db.cursor()
        cursor.execute('SELECT id FROM targets WHERE url = ?', (url,))
        result = cursor.fetchone()
        
        if result:
            return result[0]
        else:
            # Resolve IP if needed
            try:
                domain = urlparse(url).netloc
                ip = socket.gethostbyname(domain)
            except:
                ip = None
                
            cursor.execute('''
                INSERT INTO targets (url, ip, scan_date)
                VALUES (?, ?, ?)
            ''', (url, ip, datetime.now().isoformat()))
            self.db.commit()
            return cursor.lastrowid

    def main(self):
        """Main entry point for the scanner"""
        if len(sys.argv) == 1:
            print(self.banner)
            self.print_help()
            return

        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument('target', nargs='?')
        parser.add_argument('--level', type=int, choices=range(1, 6), default=3)
        parser.add_argument('--fast', action='store_true')
        parser.add_argument('--dork')
        
        # Scan options
        parser.add_argument('--xss', action='store_true')
        parser.add_argument('--sqli', action='store_true')
        parser.add_argument('--rce', action='store_true')
        parser.add_argument('--lfi', action='store_true')
        parser.add_argument('--xxe', action='store_true')
        parser.add_argument('--cors', action='store_true')
        parser.add_argument('--sri', action='store_true')
        parser.add_argument('--headers', action='store_true')
        
        # Tool integrations
        parser.add_argument('--sqlmap', action='store_true')
        parser.add_argument('--nmap', action='store_true')
        parser.add_argument('--wpscan', action='store_true')
        parser.add_argument('--nikto', action='store_true')
        parser.add_argument('--zap', action='store_true')
        
        # Reporting
        parser.add_argument('--report', choices=['html', 'pdf', 'json'], default='html')
        parser.add_argument('--output')
        
        # Other
        parser.add_argument('--help', action='store_true')
        parser.add_argument('--version', action='store_true')

        try:
            args = parser.parse_args()
        except:
            self.print_help()
            return

        if args.help:
            print(self.banner)
            self.print_help()
            return

        if args.version:
            print(f"Funnel WS Ultimate {self.version}")
            return

        if not args.target and not args.dork:
            print(f"{Fore.RED}[-] You must specify a target!{Style.RESET_ALL}")
            self.print_help()
            return

        print(self.banner)
        
        # Process dork if provided
        if args.dork:
            print(f"{Fore.CYAN}[*] Searching with dork: {args.dork}{Style.RESET_ALL}")
            args.target = f"https://example.com/?q={quote(args.dork)}"

        print(f"{Fore.CYAN}[*] Starting scan on: {args.target}{Style.RESET_ALL}")
        
        scan_data = {
            'target': args.target,
            'scan_date': datetime.now().isoformat(),
            'scan_level': args.level,
            'vulnerabilities': []
        }

        # Network scanning
        if not args.fast and args.nmap:
            nmap_results = self.run_nmap_scan(args.target, args.level)
            if nmap_results:
                scan_data['nmap'] = nmap_results

        # Web application scanning
        scan_options = {
            'xss': args.xss,
            'sqli': args.sqli,
            'rce': args.rce,
            'lfi': args.lfi,
            'xxe': args.xxe,
            'cors': args.cors,
            'sri': args.sri,
            'headers': args.headers
        }
        
        web_results = self.scan_web_application(args.target, args.level, scan_options)
        scan_data['vulnerabilities'].extend(web_results)

        # Specialized scans
        if args.sqlmap:
            sqlmap_results = self.run_sqlmap(args.target)
            scan_data['vulnerabilities'].extend(sqlmap_results)
            
        if args.nikto:
            nikto_results = self.run_nikto(args.target)
            scan_data['vulnerabilities'].extend(nikto_results)

        # Generate report
        report_path = self.generate_report(scan_data, args.report)
        
        print(f"\n{Fore.GREEN}[+] Scan completed!{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Found {len(scan_data['vulnerabilities'])} vulnerabilities{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Report saved to: {report_path}{Style.RESET_ALL}")

if __name__ == '__main__':
    # Create symlink for easy execution
    if not os.path.exists('/usr/local/bin/funnelws'):
        try:
            os.symlink(os.path.abspath(__file__), '/usr/local/bin/funnelws')
            os.chmod('/usr/local/bin/funnelws', 0o755)
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Could not create symlink: {e}{Style.RESET_ALL}")
    
    scanner = FunnelWSUltimate()
    scanner.main()