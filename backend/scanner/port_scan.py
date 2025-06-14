import socket
from urllib.parse import urlparse
import threading
import time

class PortScanner:
    def __init__(self):
        self.common_ports = [
            21,    # FTP
            22,    # SSH
            23,    # Telnet
            25,    # SMTP
            53,    # DNS
            80,    # HTTP
            110,   # POP3
            143,   # IMAP
            443,   # HTTPS
            993,   # IMAPS
            995,   # POP3S
            1433,  # MSSQL
            3306,  # MySQL
            3389,  # RDP
            5432,  # PostgreSQL
            5900,  # VNC
            6379,  # Redis
            8080,  # HTTP Alt
            8443,  # HTTPS Alt
            27017  # MongoDB
        ]
        self.open_ports = []
        self.lock = threading.Lock()
    
    def check(self, url):
        """Perform port scan on target host"""
        vulnerabilities = []
        
        try:
            # Extract hostname from URL
            parsed_url = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            hostname = parsed_url.hostname
            
            if not hostname:
                return [{
                    'type': 'Port Scan Error',
                    'severity': 'info',
                    'description': 'Could not extract hostname from URL',
                    'recommendation': 'Provide a valid URL'
                }]
            
            # Resolve hostname to IP
            try:
                ip_address = socket.gethostbyname(hostname)
            except socket.gaierror:
                return [{
                    'type': 'Port Scan Error',
                    'severity': 'info',
                    'description': f'Could not resolve hostname: {hostname}',
                    'recommendation': 'Check if the hostname is correct'
                }]
            
            self.open_ports = []
            threads = []
            
            # Create threads for port scanning
            for port in self.common_ports:
                thread = threading.Thread(target=self._scan_port, args=(ip_address, port))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Analyze results
            vulnerabilities.extend(self._analyze_open_ports(hostname, ip_address))
        
        except Exception as e:
            vulnerabilities.append({
                'type': 'Port Scan Error',
                'severity': 'info',
                'description': f'Port scanning failed: {str(e)}',
                'recommendation': 'Manual port scanning recommended'
            })
        
        return vulnerabilities
    
    def _scan_port(self, ip_address, port):
        """Scan a single port"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip_address, port))
            
            if result == 0:
                with self.lock:
                    self.open_ports.append(port)
            
            sock.close()
        except:
            pass
    
    def _analyze_open_ports(self, hostname, ip_address):
        """Analyze open ports and create vulnerability reports"""
        vulnerabilities = []
        
        if not self.open_ports:
            return vulnerabilities
        
        # Sort ports for consistent reporting
        self.open_ports.sort()
        
        # Port risk analysis
        high_risk_ports = [21, 23, 1433, 3306, 3389, 5432, 5900, 6379, 27017]
        medium_risk_ports = [22, 25, 110, 143, 993, 995]
        
        # General open ports report
        vulnerabilities.append({
            'type': 'Open Ports Discovery',
            'severity': 'info',
            'description': f'Found {len(self.open_ports)} open ports on {hostname} ({ip_address})',
            'details': f'Open ports: {", ".join(map(str, self.open_ports))}',
            'recommendation': 'Review if all open ports are necessary and properly secured'
        })
        
        # Specific port analysis
        for port in self.open_ports:
            port_info = self._get_port_info(port)
            
            if port in high_risk_ports:
                severity = 'high'
                recommendation = f'Secure or close {port_info["service"]} service if not required'
            elif port in medium_risk_ports:
                severity = 'medium'
                recommendation = f'Ensure {port_info["service"]} service is properly configured'
            else:
                continue  # Skip low-risk ports for individual reporting
            
            vulnerabilities.append({
                'type': f'{port_info["service"]} Service Exposed',
                'severity': severity,
                'description': f'{port_info["service"]} service running on port {port}',
                'details': f'{port_info["description"]}',
                'recommendation': recommendation
            })
        
        return vulnerabilities
    
    def _get_port_info(self, port):
        """Get information about a specific port"""
        port_info = {
            21: {'service': 'FTP', 'description': 'File Transfer Protocol - often allows anonymous access'},
            22: {'service': 'SSH', 'description': 'Secure Shell - ensure strong authentication'},
            23: {'service': 'Telnet', 'description': 'Unencrypted remote access - highly insecure'},
            25: {'service': 'SMTP', 'description': 'Mail server - check for open relay'},
            53: {'service': 'DNS', 'description': 'Domain Name System'},
            80: {'service': 'HTTP', 'description': 'Web server - standard HTTP port'},
            110: {'service': 'POP3', 'description': 'Mail retrieval - consider encrypted alternatives'},
            143: {'service': 'IMAP', 'description': 'Mail access - consider encrypted alternatives'},
            443: {'service': 'HTTPS', 'description': 'Secure web server'},
            993: {'service': 'IMAPS', 'description': 'Secure IMAP'},
            995: {'service': 'POP3S', 'description': 'Secure POP3'},
            1433: {'service': 'MSSQL', 'description': 'Microsoft SQL Server - should not be exposed'},
            3306: {'service': 'MySQL', 'description': 'MySQL database - should not be exposed'},
            3389: {'service': 'RDP', 'description': 'Remote Desktop - high security risk'},
            5432: {'service': 'PostgreSQL', 'description': 'PostgreSQL database - should not be exposed'},
            5900: {'service': 'VNC', 'description': 'Virtual Network Computing - often insecure'},
            6379: {'service': 'Redis', 'description': 'Redis database - should not be exposed'},
            8080: {'service': 'HTTP-Alt', 'description': 'Alternative HTTP port'},
            8443: {'service': 'HTTPS-Alt', 'description': 'Alternative HTTPS port'},
            27017: {'service': 'MongoDB', 'description': 'MongoDB database - should not be exposed'}
        }
        
        return port_info.get(port, {
            'service': f'Port {port}',
            'description': f'Unknown service running on port {port}'
        })