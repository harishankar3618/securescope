import requests
import re
from urllib.parse import urljoin, urlparse
import time

class SensitiveInfoScanner:
    def __init__(self):
        self.sensitive_files = [
            'robots.txt',
            'sitemap.xml',
            '.htaccess',
            '.env',
            'config.php',
            'wp-config.php',
            'database.php',
            'settings.php',
            'web.config',
            'phpinfo.php',
            'info.php',
            'test.php',
            'backup.sql',
            'dump.sql',
            'readme.txt',
            'changelog.txt',
            'license.txt',
            'composer.json',
            'package.json'
        ]
        
        self.sensitive_patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'phone': r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b',
            'credit_card': r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'api_key': r'(?i)(api_key|apikey|api-key)[\s=:]+["\']?[a-zA-Z0-9]{20,}["\']?',
            'password': r'(?i)(password|passwd|pwd)[\s=:]+["\']?[^\s"\'<>]{6,}["\']?',
            'database_url': r'(?i)(database_url|db_url)[\s=:]+["\']?[^\s"\'<>]+["\']?',
            'secret_key': r'(?i)(secret_key|secret)[\s=:]+["\']?[a-zA-Z0-9]{20,}["\']?'
        }
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check(self, url):
        """Scan for sensitive information exposure"""
        vulnerabilities = []
        
        try:
            # Check main page first
            main_page_vulns = self._scan_page_content(url)
            vulnerabilities.extend(main_page_vulns)
            
            # Check for sensitive files
            file_vulns = self._scan_sensitive_files(url)
            vulnerabilities.extend(file_vulns)
            
        except Exception as e:
            vulnerabilities.append({
                'type': 'Sensitive Info Scan Error',
                'severity': 'info',
                'description': f'Sensitive information scanning failed: {str(e)}',
                'recommendation': 'Manual review recommended'
            })
        
        return vulnerabilities
    
    def _scan_page_content(self, url):
        """Scan page content for sensitive information"""
        vulnerabilities = []
        
        try:
            response = self.session.get(url, timeout=10)
            content = response.text
            
            # Check for sensitive patterns
            for pattern_name, pattern in self.sensitive_patterns.items():
                matches = re.findall(pattern, content)
                
                if matches:
                    # Filter out common false positives
                    filtered_matches = self._filter_matches(pattern_name, matches)
                    
                    if filtered_matches:
                        severity = self._get_pattern_severity(pattern_name)
                        vulnerabilities.append({
                            'type': f'Sensitive Information Exposure - {pattern_name.title()}',
                            'severity': severity,
                            'description': f'Found {len(filtered_matches)} potential {pattern_name} disclosure(s)',
                            'details': f'Sample: {filtered_matches[0][:50]}...' if len(filtered_matches[0]) > 50 else f'Found: {filtered_matches[0]}',
                            'recommendation': f'Remove or protect {pattern_name} information from public pages'
                        })
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _scan_sensitive_files(self, url):
        """Scan for sensitive files"""
        vulnerabilities = []
        
        for filename in self.sensitive_files:
            try:
                file_url = urljoin(url.rstrip('/') + '/', filename)
                response = self.session.get(file_url, timeout=5)
                
                if response.status_code == 200 and len(response.text) > 0:
                    severity = self._get_file_severity(filename)
                    
                    vulnerability = {
                        'type': f'Sensitive File Exposure - {filename}',
                        'severity': severity,
                        'description': f'Sensitive file "{filename}" is publicly accessible',
                        'details': f'File found at: {file_url}',
                        'recommendation': self._get_file_recommendation(filename)
                    }
                    
                    # Check file content for additional sensitive info
                    content_analysis = self._analyze_file_content(filename, response.text)
                    if content_analysis:
                        vulnerability['details'] += f' | {content_analysis}'
                    
                    vulnerabilities.append(vulnerability)
                
                time.sleep(0.1)  # Rate limiting
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _filter_matches(self, pattern_name, matches):
        """Filter out common false positives"""
        filtered = []
        
        for match in matches:
            if pattern_name == 'email':
                # Skip common non-personal emails
                if not any(common in match.lower() for common in ['admin@', 'info@', 'contact@', 'noreply@', 'no-reply@']):
                    filtered.append(match)
            elif pattern_name == 'password':
                # Skip common non-password patterns
                if not any(common in match.lower() for common in ['password:', 'password=', 'example', 'test', '****']):
                    filtered.append(match)
            else:
                filtered.append(match)
        
        # Limit to first 3 matches to avoid spam
        return filtered[:3]
    
    def _get_pattern_severity(self, pattern_name):
        """Get severity level for different pattern types"""
        high_severity = ['credit_card', 'ssn', 'api_key', 'secret_key', 'password', 'database_url']
        medium_severity = ['email', 'phone']
        
        if pattern_name in high_severity:
            return 'high'
        elif pattern_name in medium_severity:
            return 'medium'
        else:
            return 'low'
    
    def _get_file_severity(self, filename):
        """Get severity level for different file types"""
        high_risk = ['.env', 'config.php', 'wp-config.php', 'database.php', 'web.config', 'backup.sql', 'dump.sql']
        medium_risk = ['phpinfo.php', 'info.php', 'test.php', '.htaccess']
        
        if filename in high_risk:
            return 'high'
        elif filename in medium_risk:
            return 'medium'
        else:
            return 'low'
    
    def _get_file_recommendation(self, filename):
        """Get specific recommendations for different files"""
        recommendations = {
            '.env': 'Remove .env file from web directory - contains sensitive configuration',
            'robots.txt': 'Review robots.txt for sensitive path disclosure',
            'phpinfo.php': 'Remove phpinfo.php - exposes server configuration',
            'config.php': 'Move configuration file outside web root',
            'wp-config.php': 'Secure WordPress configuration file',
            '.htaccess': 'Ensure .htaccess does not expose sensitive rules',
            'backup.sql': 'Remove database backup from web directory',
            'composer.json': 'Review for sensitive dependency information'
        }
        
        return recommendations.get(filename, f'Secure or remove {filename} from public access')
    
    def _analyze_file_content(self, filename, content):
        """Analyze file content for additional sensitive information"""
        if filename == 'robots.txt':
            disallowed = re.findall(r'Disallow:\s*(.+)', content, re.IGNORECASE)
            if disallowed:
                return f'Reveals {len(disallowed)} hidden directories'
        
        elif filename in ['phpinfo.php', 'info.php']:
            if 'PHP Version' in content:
                return 'Exposes PHP configuration and server details'
        
        elif filename == '.env':
            env_vars = len(re.findall(r'^[A-Z_]+=', content, re.MULTILINE))
            if env_vars > 0:
                return f'Contains {env_vars} environment variables'
        
        return None