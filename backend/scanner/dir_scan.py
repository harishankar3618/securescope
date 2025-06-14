import requests
from urllib.parse import urljoin
import time

class DirectoryScanner:
    def __init__(self):
        self.common_dirs = [
            'admin', 'admin.php', 'administrator', 'wp-admin',
            'backup', 'backups', 'config', 'database',
            'db', 'logs', 'log', 'temp', 'tmp',
            'uploads', 'upload', 'files', 'images',
            'css', 'js', 'assets', 'static',
            'api', 'test', 'tests', 'dev',
            'phpmyadmin', 'phpinfo.php', 'info.php',
            'robots.txt', 'sitemap.xml', '.htaccess',
            '.env', '.git', '.svn', 'composer.json'
        ]
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def check(self, url):
        """Scan for common directories and files"""
        vulnerabilities = []
        found_dirs = []
        
        try:
            # Get base response for comparison
            try:
                base_response = self.session.get(url, timeout=10)
                base_status = base_response.status_code
            except:
                base_status = 404
            
            for directory in self.common_dirs:
                test_url = urljoin(url.rstrip('/') + '/', directory)
                
                try:
                    response = self.session.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Check for interesting responses
                    if response.status_code in [200, 301, 302, 403]:
                        severity = self._assess_severity(directory, response.status_code)
                        found_dirs.append({
                            'url': test_url,
                            'status': response.status_code,
                            'directory': directory,
                            'severity': severity
                        })
                
                except:
                    continue
                
                time.sleep(0.1)  # Rate limiting
            
            # Generate vulnerability reports
            for found_dir in found_dirs:
                vulnerability = self._create_vulnerability_report(found_dir)
                if vulnerability:
                    vulnerabilities.append(vulnerability)
        
        except Exception as e:
            vulnerabilities.append({
                'type': 'Directory Scan Error',
                'severity': 'info',
                'description': f'Directory scanning failed: {str(e)}',
                'recommendation': 'Manual directory enumeration recommended'
            })
        
        return vulnerabilities
    
    def _assess_severity(self, directory, status_code):
        """Assess the severity of a found directory"""
        high_risk_dirs = [
            'admin', 'administrator', 'wp-admin', 'phpmyadmin',
            'backup', 'backups', 'database', 'db', 'logs', 'log',
            '.env', '.git', '.svn', 'config'
        ]
        
        medium_risk_dirs = [
            'uploads', 'upload', 'files', 'temp', 'tmp',
            'phpinfo.php', 'info.php', 'test', 'tests', 'dev'
        ]
        
        # Status 403 (Forbidden) indicates directory exists but is protected
        if status_code == 403:
            if any(risk_dir in directory.lower() for risk_dir in high_risk_dirs):
                return 'medium'
            return 'low'
        
        # Status 200 (OK) indicates accessible directory
        if status_code == 200:
            if any(risk_dir in directory.lower() for risk_dir in high_risk_dirs):
                return 'high'
            elif any(risk_dir in directory.lower() for risk_dir in medium_risk_dirs):
                return 'medium'
            return 'low'
        
        # Redirects might indicate directory exists
        if status_code in [301, 302]:
            return 'low'
        
        return 'info'
    
    def _create_vulnerability_report(self, found_dir):
        """Create vulnerability report for found directory"""
        directory = found_dir['directory']
        status = found_dir['status']
        severity = found_dir['severity']
        url = found_dir['url']
        
        # Skip low-severity common directories
        if severity == 'low' and directory in ['css', 'js', 'assets', 'static', 'images']:
            return None
        
        descriptions = {
            'admin': 'Administrative interface discovered',
            'wp-admin': 'WordPress admin panel found',
            'phpmyadmin': 'phpMyAdmin interface exposed',
            'backup': 'Backup directory accessible',
            'database': 'Database directory found',
            'logs': 'Log files directory accessible',
            '.env': 'Environment configuration file exposed',
            '.git': 'Git repository exposed',
            'phpinfo.php': 'PHP info page accessible',
            'config': 'Configuration directory found'
        }
        
        description = descriptions.get(directory, f'Directory "{directory}" found')
        
        recommendations = {
            'high': 'Restrict access to sensitive directories immediately',
            'medium': 'Review directory permissions and content',
            'low': 'Consider restricting access if sensitive'
        }
        
        return {
            'type': 'Directory Enumeration',
            'severity': severity,
            'description': f'{description} (Status: {status})',
            'details': f'Found at: {url}',
            'recommendation': recommendations.get(severity, 'Review directory accessibility')
        }