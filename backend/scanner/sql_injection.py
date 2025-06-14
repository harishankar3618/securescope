import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import re
import time

class SQLInjectionChecker:
    def __init__(self):
        self.timeout = 10
        self.payloads = [
            "'", '"', "1'", "1\"", "1' OR '1'='1", "1\" OR \"1\"=\"1",
            "' OR 1=1--", "\" OR 1=1--", "'; DROP TABLE users--",
            "1' UNION SELECT NULL--", "1' AND 1=1--", "1' AND 1=2--",
            "1' OR SLEEP(5)--", "1'; WAITFOR DELAY '00:00:05'--",
            "1' OR pg_sleep(5)--", "admin'--", "admin\"--"
        ]
        
        self.error_patterns = [
            r"sql syntax.*mysql",
            r"warning.*mysql_.*",
            r"valid mysql result",
            r"mysqlclient\.",
            r"postgresql.*error",
            r"warning.*pg_.*",
            r"valid postgresql result",
            r"npgsql\.",
            r"driver.* sql server",
            r"ole db.* sql server",
            r"(\[sql server\]|\[odbc sql server driver\])",
            r"microsoft access.*driver",
            r"microsoft jet database engine",
            r"oracle error",
            r"oracle.*driver",
            r"warning.*oci_.*",
            r"warning.*ora_.*",
            r"sqlite.*error",
            r"warning.*sqlite_.*",
            r"pdo_sqlite",
            r"sql error.*pdo\.",
            r"warning.*pdo_.*"
        ]
    
    def check(self, url):
        """Test for SQL injection vulnerabilities"""
        vulnerabilities = []
        
        try:
            # Parse URL to extract parameters
            parsed_url = urlparse(url)
            params = parse_qs(parsed_url.query)
            
            if not params:
                # Try to find forms with input fields
                try:
                    response = requests.get(url, timeout=self.timeout)
                    forms = self._extract_forms(response.text)
                    if forms:
                        vulnerabilities.extend(self._test_forms(url, forms))
                except:
                    pass
                
                # No parameters found
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'title': 'No Parameters to Test',
                    'description': 'No URL parameters or forms found for SQL injection testing',
                    'severity': 'info',
                    'impact': 'Cannot determine SQL injection vulnerability status',
                    'recommendation': 'Test individual pages with parameters or forms'
                })
                return vulnerabilities
            
            # Test each parameter
            for param_name, param_values in params.items():
                if param_values:
                    original_value = param_values[0]
                    vulnerabilities.extend(self._test_parameter(url, param_name, original_value))
        
        except Exception as e:
            vulnerabilities.append({
                'type': 'SQL Injection',
                'title': 'SQL Injection Test Failed',
                'description': f'Error during SQL injection testing: {str(e)}',
                'severity': 'info',
                'impact': 'Unable to test for SQL injection vulnerabilities',
                'recommendation': 'Manually test for SQL injection vulnerabilities'
            })
        
        return vulnerabilities
    
    def _test_parameter(self, url, param_name, original_value):
        """Test a specific parameter for SQL injection"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        
        try:
            # Get baseline response
            baseline_response = requests.get(url, timeout=self.timeout)
            baseline_time = baseline_response.elapsed.total_seconds()
            baseline_content = baseline_response.text
            
            for payload in self.payloads:
                try:
                    # Create modified URL with payload
                    params = parse_qs(parsed_url.query)
                    params[param_name] = [payload]
                    new_query = urlencode(params, doseq=True)
                    test_url = urlunparse(parsed_url._replace(query=new_query))
                    
                    # Send request with payload
                    start_time = time.time()
                    response = requests.get(test_url, timeout=self.timeout)
                    response_time = time.time() - start_time
                    
                    # Check for SQL errors in response
                    if self._check_sql_errors(response.text):
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'title': f'SQL Injection in Parameter: {param_name}',
                            'description': f'SQL error detected when testing parameter "{param_name}" with payload: {payload}',
                            'severity': 'critical',
                            'impact': 'Database information could be extracted or modified',
                            'recommendation': 'Use parameterized queries and input validation'
                        })
                        break
                    
                    # Check for time-based SQL injection
                    if 'sleep' in payload.lower() or 'waitfor' in payload.lower():
                        if response_time > 4:  # Significant delay
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'title': f'Time-based SQL Injection in Parameter: {param_name}',
                                'description': f'Time delay detected when testing parameter "{param_name}" with payload: {payload}',
                                'severity': 'critical',
                                'impact': 'Database information could be extracted through time-based attacks',
                                'recommendation': 'Use parameterized queries and input validation'
                            })
                            break
                    
                    # Check for boolean-based differences
                    if len(response.text) != len(baseline_content):
                        # Simple content length difference check
                        difference_ratio = abs(len(response.text) - len(baseline_content)) / len(baseline_content)
                        if difference_ratio > 0.1:  # 10% difference threshold
                            vulnerabilities.append({
                                'type': 'SQL Injection',
                                'title': f'Potential SQL Injection in Parameter: {param_name}',
                                'description': f'Response content significantly changed with payload: {payload}',
                                'severity': 'high',
                                'impact': 'Possible SQL injection vulnerability',
                                'recommendation': 'Investigate parameter for SQL injection and use parameterized queries'
                            })
                
                except requests.RequestException:
                    continue
                except Exception:
                    continue
        
        except Exception as e:
            vulnerabilities.append({
                'type': 'SQL Injection',
                'title': f'Parameter Test Failed: {param_name}',
                'description': f'Error testing parameter {param_name}: {str(e)}',
                'severity': 'info',
                'impact': 'Unable to test parameter for SQL injection',
                'recommendation': 'Manually test this parameter for SQL injection'
            })
        
        return vulnerabilities
    
    def _check_sql_errors(self, content):
        """Check if response contains SQL error patterns"""
        content_lower = content.lower()
        for pattern in self.error_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        return False
    
    def _extract_forms(self, html_content):
        """Extract forms from HTML content"""
        forms = []
        try:
            # Simple form extraction - in production, use BeautifulSoup
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*name=["\']([^"\']*)["\'][^>]*>'
            
            for form_match in re.finditer(form_pattern, html_content, re.IGNORECASE | re.DOTALL):
                action = form_match.group(1)
                form_content = form_match.group(2)
                
                inputs = []
                for input_match in re.finditer(input_pattern, form_content, re.IGNORECASE):
                    inputs.append(input_match.group(1))
                
                if inputs:
                    forms.append({'action': action, 'inputs': inputs})
        except:
            pass
        
        return forms
    
    def _test_forms(self, base_url, forms):
        """Test forms for SQL injection"""
        vulnerabilities = []
        
        for form in forms[:2]:  # Limit to first 2 forms
            try:
                form_url = form['action']
                if not form_url.startswith('http'):
                    parsed_base = urlparse(base_url)
                    if form_url.startswith('/'):
                        form_url = f"{parsed_base.scheme}://{parsed_base.netloc}{form_url}"
                    else:
                        form_url = f"{base_url.rstrip('/')}/{form_url}"
                
                # Test first few form inputs
                for input_name in form['inputs'][:3]:
                    for payload in self.payloads[:5]:  # Limit payloads for forms
                        try:
                            data = {input_name: payload}
                            response = requests.post(form_url, data=data, timeout=self.timeout)
                            
                            if self._check_sql_errors(response.text):
                                vulnerabilities.append({
                                    'type': 'SQL Injection',
                                    'title': f'SQL Injection in Form Field: {input_name}',
                                    'description': f'SQL error detected in form field "{input_name}"',
                                    'severity': 'critical',
                                    'impact': 'Form submission vulnerable to SQL injection',
                                    'recommendation': 'Use parameterized queries for form processing'
                                })
                                break
                        except:
                            continue
            except:
                continue
        
        return vulnerabilities