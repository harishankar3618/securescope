import requests
from urllib.parse import urlparse

class HeadersChecker:
    def __init__(self):
        self.timeout = 10
        self.required_headers = {
            'content-security-policy': {
                'severity': 'high',
                'title': 'Missing Content Security Policy',
                'description': 'Content-Security-Policy header is not present',
                'impact': 'Website is vulnerable to XSS and data injection attacks',
                'recommendation': 'Implement Content-Security-Policy header to prevent XSS attacks'
            },
            'x-frame-options': {
                'severity': 'medium',
                'title': 'Missing X-Frame-Options',
                'description': 'X-Frame-Options header is not present',
                'impact': 'Website may be vulnerable to clickjacking attacks',
                'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
            },
            'strict-transport-security': {
                'severity': 'medium',
                'title': 'Missing Strict Transport Security',
                'description': 'Strict-Transport-Security header is not present',
                'impact': 'Website is vulnerable to protocol downgrade attacks',
                'recommendation': 'Implement HSTS header to enforce HTTPS connections'
            },
            'x-content-type-options': {
                'severity': 'low',
                'title': 'Missing X-Content-Type-Options',
                'description': 'X-Content-Type-Options header is not present',
                'impact': 'Browser may perform MIME type sniffing attacks',
                'recommendation': 'Set X-Content-Type-Options to nosniff'
            },
            'referrer-policy': {
                'severity': 'low',
                'title': 'Missing Referrer Policy',
                'description': 'Referrer-Policy header is not present',
                'impact': 'Referrer information may leak to external sites',
                'recommendation': 'Set appropriate Referrer-Policy header'
            },
            'permissions-policy': {
                'severity': 'low',
                'title': 'Missing Permissions Policy',
                'description': 'Permissions-Policy header is not present',
                'impact': 'Browser features are not restricted',
                'recommendation': 'Implement Permissions-Policy to control browser features'
            }
        }
    
    def check(self, url):
        """Check for security headers"""
        vulnerabilities = []
        
        try:
            response = requests.get(url, timeout=self.timeout, allow_redirects=True)
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check for missing security headers
            for header_name, header_info in self.required_headers.items():
                if header_name not in headers:
                    vulnerabilities.append({
                        'type': 'Security Headers',
                        'title': header_info['title'],
                        'description': header_info['description'],
                        'severity': header_info['severity'],
                        'impact': header_info['impact'],
                        'recommendation': header_info['recommendation']
                    })
            
            # Check for weak security header values
            if 'content-security-policy' in headers:
                csp = headers['content-security-policy'].lower()
                if 'unsafe-inline' in csp or 'unsafe-eval' in csp:
                    vulnerabilities.append({
                        'type': 'Security Headers',
                        'title': 'Weak Content Security Policy',
                        'description': 'CSP contains unsafe-inline or unsafe-eval directives',
                        'severity': 'medium',
                        'impact': 'Reduced protection against XSS attacks',
                        'recommendation': 'Remove unsafe-inline and unsafe-eval from CSP'
                    })
                if '*' in csp:
                    vulnerabilities.append({
                        'type': 'Security Headers',
                        'title': 'Overly Permissive CSP',
                        'description': 'CSP contains wildcard (*) sources',
                        'severity': 'medium',
                        'impact': 'CSP provides minimal protection',
                        'recommendation': 'Use specific sources instead of wildcards in CSP'
                    })
            
            if 'x-frame-options' in headers:
                xfo = headers['x-frame-options'].lower()
                if xfo not in ['deny', 'sameorigin']:
                    vulnerabilities.append({
                        'type': 'Security Headers',
                        'title': 'Weak X-Frame-Options',
                        'description': f'X-Frame-Options set to: {xfo}',
                        'severity': 'low',
                        'impact': 'May not provide adequate clickjacking protection',
                        'recommendation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
                    })
            
            # Check for information disclosure headers
            dangerous_headers = [
                'server', 'x-powered-by', 'x-aspnet-version', 
                'x-generator', 'x-drupal-cache'
            ]
            
            for header in dangerous_headers:
                if header in headers:
                    vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'title': f'Server Information Disclosure',
                        'description': f'{header} header reveals server information: {headers[header]}',
                        'severity': 'info',
                        'impact': 'Server/technology stack information disclosed',
                        'recommendation': f'Remove or obfuscate {header} header'
                    })
            
            # Check HSTS configuration
            if 'strict-transport-security' in headers:
                hsts = headers['strict-transport-security']
                if 'max-age=' in hsts:
                    max_age = hsts.split('max-age=')[1].split(';')[0]
                    try:
                        max_age_seconds = int(max_age)
                        if max_age_seconds < 31536000:  # Less than 1 year
                            vulnerabilities.append({
                                'type': 'Security Headers',
                                'title': 'Short HSTS Max-Age',
                                'description': f'HSTS max-age is only {max_age_seconds} seconds',
                                'severity': 'low',
                                'impact': 'HSTS protection expires quickly',
                                'recommendation': 'Set HSTS max-age to at least 31536000 (1 year)'
                            })
                    except ValueError:
                        vulnerabilities.append({
                            'type': 'Security Headers',
                            'title': 'Invalid HSTS Configuration',
                            'description': 'HSTS header has invalid max-age value',
                            'severity': 'medium',
                            'impact': 'HSTS protection may not work correctly',
                            'recommendation': 'Fix HSTS max-age directive'
                        })
        
        except requests.RequestException as e:
            vulnerabilities.append({
                'type': 'Security Headers',
                'title': 'Headers Check Failed',
                'description': f'Could not retrieve headers: {str(e)}',
                'severity': 'info',
                'impact': 'Unable to verify security headers',
                'recommendation': 'Ensure website is accessible and retry scan'
            })
        except Exception as e:
            vulnerabilities.append({
                'type': 'Security Headers',
                'title': 'Headers Analysis Error',
                'description': f'Error analyzing headers: {str(e)}',
                'severity': 'info',
                'impact': 'Security headers analysis incomplete',
                'recommendation': 'Manually verify security headers configuration'
            })
        
        return vulnerabilities