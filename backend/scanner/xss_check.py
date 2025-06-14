import requests
import re
from urllib.parse import urljoin, urlparse
import time

class XSSChecker:
    def __init__(self):
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check(self, url):
        """Check for XSS vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Get the main page first
            response = self.session.get(url, timeout=10)
            
            # Find forms and input fields
            forms = self._find_forms(response.text)
            
            for form in forms:
                form_url = urljoin(url, form.get('action', ''))
                method = form.get('method', 'GET').upper()
                
                # Test each payload
                for payload in self.payloads:
                    vulnerability = self._test_payload(form_url, method, form, payload)
                    if vulnerability:
                        vulnerabilities.append(vulnerability)
                        break  # One payload sufficient per form
                
                time.sleep(0.5)  # Rate limiting
        
        except Exception as e:
            vulnerabilities.append({
                'type': 'XSS Check Error',
                'severity': 'info',
                'description': f'XSS scanning failed: {str(e)}',
                'recommendation': 'Manual testing recommended'
            })
        
        return vulnerabilities
    
    def _find_forms(self, html):
        """Extract forms from HTML"""
        forms = []
        form_pattern = r'<form[^>]*>(.*?)</form>'
        
        for form_match in re.finditer(form_pattern, html, re.DOTALL | re.IGNORECASE):
            form_html = form_match.group(0)
            
            # Extract form attributes
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            
            # Extract input fields
            inputs = []
            input_pattern = r'<input[^>]*>'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                input_html = input_match.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
                if name_match:
                    inputs.append({
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text'
                    })
            
            forms.append({
                'action': action_match.group(1) if action_match else '',
                'method': method_match.group(1) if method_match else 'GET',
                'inputs': inputs
            })
        
        return forms
    
    def _test_payload(self, url, method, form, payload):
        """Test a specific XSS payload"""
        try:
            # Prepare form data
            data = {}
            for input_field in form['inputs']:
                if input_field['type'].lower() not in ['submit', 'button', 'hidden']:
                    data[input_field['name']] = payload
            
            if method == 'POST':
                response = self.session.post(url, data=data, timeout=10)
            else:
                response = self.session.get(url, params=data, timeout=10)
            
            # Check if payload is reflected in response
            if payload in response.text:
                return {
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'high',
                    'description': f'Potential XSS vulnerability found in form at {url}',
                    'details': f'Payload "{payload}" was reflected in the response',
                    'recommendation': 'Implement input validation and output encoding'
                }
        
        except Exception:
            pass
        
        return None