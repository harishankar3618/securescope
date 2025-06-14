from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import datetime
from scanner.ssl_check import SSLChecker
from scanner.headers_check import HeadersChecker
from scanner.sql_injection import SQLInjectionChecker
from scanner.xss_check import XSSChecker
from scanner.dir_scan import DirectoryScanner
from scanner.port_scan import PortScanner
from scanner.sensitive_info import SensitiveInfoScanner

app = Flask(__name__)
CORS(app)

class VulnerabilityScanner:
    def __init__(self):
        self.ssl_checker = SSLChecker()
        self.headers_checker = HeadersChecker()
        self.sql_checker = SQLInjectionChecker()
        self.xss_checker = XSSChecker()
        self.dir_scanner = DirectoryScanner()
        self.port_scanner = PortScanner()
        self.sensitive_scanner = SensitiveInfoScanner()
    
    def scan_url(self, url):
        """Perform comprehensive security scan on given URL"""
        results = {
            'url': url,
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerabilities': [],
            'summary': {
                'total_issues': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
        }
        
        try:
            # SSL/HTTPS Check
            ssl_results = self.ssl_checker.check(url)
            results['vulnerabilities'].extend(ssl_results)
            
            # Security Headers Check
            headers_results = self.headers_checker.check(url)
            results['vulnerabilities'].extend(headers_results)
            
            # SQL Injection Check
            sql_results = self.sql_checker.check(url)
            results['vulnerabilities'].extend(sql_results)
            
            # XSS Check
            xss_results = self.xss_checker.check(url)
            results['vulnerabilities'].extend(xss_results)
            
            # Directory Scanning
            dir_results = self.dir_scanner.check(url)
            results['vulnerabilities'].extend(dir_results)
            
            # Port Scanning
            port_results = self.port_scanner.check(url)
            results['vulnerabilities'].extend(port_results)
            
            # Sensitive Information Check
            sensitive_results = self.sensitive_scanner.check(url)
            results['vulnerabilities'].extend(sensitive_results)
            
            # Calculate summary
            for vuln in results['vulnerabilities']:
                results['summary']['total_issues'] += 1
                severity = vuln.get('severity', 'info').lower()
                if severity in results['summary']:
                    results['summary'][severity] += 1
            
            return results
            
        except Exception as e:
            return {
                'error': f'Scan failed: {str(e)}',
                'url': url,
                'timestamp': datetime.datetime.now().isoformat()
            }

scanner = VulnerabilityScanner()

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    """Main scanning endpoint"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'URL is required'}), 400
        
        url = data['url'].strip()
        if not url:
            return jsonify({'error': 'URL cannot be empty'}), 400
        
        # Basic URL validation
        if not (url.startswith('http://') or url.startswith('https://')):
            url = 'https://' + url
        
        results = scanner.scan_url(url)
        
        if 'error' in results:
            return jsonify(results), 500
        
        return jsonify(results)
        
    except Exception as e:
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.datetime.now().isoformat()})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)