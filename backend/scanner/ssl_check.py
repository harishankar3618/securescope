import requests
import ssl
import socket
from urllib.parse import urlparse
import datetime

class SSLChecker:
    def __init__(self):
        self.timeout = 10

    def check(self, url):
        """Check SSL/HTTPS configuration"""
        vulnerabilities = []
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        try:
            # Check if HTTPS is enforced
            if parsed_url.scheme == 'http':
                vulnerabilities.append({
                    'type': 'SSL/TLS',
                    'title': 'HTTPS Not Enforced',
                    'description': 'Website is accessible over HTTP (unencrypted connection)',
                    'severity': 'high',
                    'impact': 'Data transmitted between client and server is not encrypted',
                    'recommendation': 'Enforce HTTPS and redirect all HTTP traffic to HTTPS'
                })

                # Try to access HTTPS version
                try:
                    https_url = url.replace('http://', 'https://')
                    response = requests.get(https_url, timeout=self.timeout, verify=False)
                    if response.status_code == 200:
                        vulnerabilities.append({
                            'type': 'SSL/TLS',
                            'title': 'HTTPS Available but Not Enforced',
                            'description': 'HTTPS is available but HTTP is not redirected',
                            'severity': 'medium',
                            'impact': 'Users may accidentally use insecure HTTP connection',
                            'recommendation': 'Configure automatic HTTP to HTTPS redirection'
                        })
                except:
                    pass
            else:
                # Check SSL certificate details
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((hostname, 443), timeout=self.timeout) as sock:
                        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                            cert = ssock.getpeercert()

                            # Check certificate expiration
                            not_after = cert.get('notAfter') if cert else None
                            if isinstance(not_after, str):
                                expiry_date = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                                days_until_expiry = (expiry_date - datetime.datetime.utcnow()).days

                                if days_until_expiry < 30:
                                    severity = 'critical' if days_until_expiry < 7 else 'high'
                                    vulnerabilities.append({
                                        'type': 'SSL/TLS',
                                        'title': 'SSL Certificate Expiring Soon',
                                        'description': f'SSL certificate expires in {days_until_expiry} days',
                                        'severity': severity,
                                        'impact': 'Website will become inaccessible when certificate expires',
                                        'recommendation': 'Renew SSL certificate immediately'
                                    })
                            else:
                                vulnerabilities.append({
                                    'type': 'SSL/TLS',
                                    'title': 'Unexpected Certificate Format',
                                    'description': 'Could not parse "notAfter" field in certificate',
                                    'severity': 'medium',
                                    'impact': 'May not detect certificate expiration accurately',
                                    'recommendation': 'Check certificate format or manually validate'
                                })

                            # Check if certificate is self-signed
                            if cert and cert.get('issuer') == cert.get('subject'):
                                vulnerabilities.append({
                                    'type': 'SSL/TLS',
                                    'title': 'Self-Signed Certificate',
                                    'description': 'Website uses a self-signed SSL certificate',
                                    'severity': 'high',
                                    'impact': 'Browsers will show security warnings to users',
                                    'recommendation': 'Use a certificate from a trusted Certificate Authority'
                                })

                except ssl.SSLError as e:
                    vulnerabilities.append({
                        'type': 'SSL/TLS',
                        'title': 'SSL Configuration Error',
                        'description': f'SSL handshake failed: {str(e)}',
                        'severity': 'high',
                        'impact': 'SSL connection cannot be established',
                        'recommendation': 'Fix SSL configuration issues'
                    })
                except Exception as e:
                    vulnerabilities.append({
                        'type': 'SSL/TLS',
                        'title': 'SSL Check Failed',
                        'description': f'Unable to verify SSL configuration: {str(e)}',
                        'severity': 'medium',
                        'impact': 'SSL status unknown',
                        'recommendation': 'Manually verify SSL configuration'
                    })

                # Test SSL/TLS protocols
                try:
                    response = requests.get(url, timeout=self.timeout)
                    if hasattr(response.raw, 'version') and response.raw.version < 11:
                        vulnerabilities.append({
                            'type': 'SSL/TLS',
                            'title': 'Weak TLS Version',
                            'description': 'Server supports weak TLS versions',
                            'severity': 'medium',
                            'impact': 'Connection may be vulnerable to downgrade attacks',
                            'recommendation': 'Disable TLS 1.0 and 1.1, use TLS 1.2 or higher'
                        })
                except:
                    pass

        except Exception as e:
            vulnerabilities.append({
                'type': 'SSL/TLS',
                'title': 'SSL Analysis Failed',
                'description': f'Could not analyze SSL configuration: {str(e)}',
                'severity': 'info',
                'impact': 'Unable to determine SSL security status',
                'recommendation': 'Manually verify SSL configuration'
            })

        return vulnerabilities
