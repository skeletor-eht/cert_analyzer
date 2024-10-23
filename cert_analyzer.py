import ssl
import socket
import datetime
import OpenSSL.crypto
import requests
import hashlib
from urllib.parse import urlparse
import concurrent.futures
import re

def get_certificate_and_connection_info(domain, port=443):
    """
    Fetch the SSL certificate and connection information for a given domain.
    
    Args:
        domain (str): The domain to fetch the certificate from (e.g., 'google.com')
        port (int): The port to connect to (default is 443 for HTTPS)
    
    Returns:
        tuple: (certificate object, connection info dict) or (None, None) if failed
    """
    try:
        # Create SSL context
        context = ssl.create_default_context()
        
        # Create socket connection
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                # Get the certificate in PEM format
                cert_binary = ssock.getpeercert(binary_form=True)
                # Convert to OpenSSL certificate
                cert = OpenSSL.crypto.load_certificate(
                    OpenSSL.crypto.FILETYPE_ASN1,
                    cert_binary
                )
                
                # Get connection information
                connection_info = {
                    'tls_version': ssock.version(),
                    'cipher': ssock.cipher(),
                    'compression': ssock.compression()
                }
                
                return cert, connection_info
    
    except Exception as e:
        print(f"Error fetching certificate for {domain}: {str(e)}")
        return None, None

def analyze_cert_and_connection_info(domain):
    """
    Get comprehensive information about a certificate and its TLS connection.
    
    Args:
        domain (str): The domain to analyze
    
    Returns:
        dict: Certificate and connection information
    """
    cert, conn_info = get_certificate_and_connection_info(domain)
    if not cert:
        return None
    
    try:
        info = {
            'domain': domain,
            'valid_from': datetime.datetime.strptime(
                cert.get_notBefore().decode('ascii'),
                '%Y%m%d%H%M%SZ'
            ),
            'valid_until': datetime.datetime.strptime(
                cert.get_notAfter().decode('ascii'),
                '%Y%m%d%H%M%SZ'
            ),
            'issuer': dict(cert.get_issuer().get_components()),
            'subject': dict(cert.get_subject().get_components()),
            'version': cert.get_version(),
            'serial_number': cert.get_serial_number(),
            'signature_algorithm': cert.get_signature_algorithm().decode('ascii'),
        }
        
        # Add connection information
        if conn_info:
            info['tls_version'] = conn_info['tls_version']
            info['cipher_suite'] = {
                'name': conn_info['cipher'][0],
                'version': conn_info['cipher'][1],
                'bits': conn_info['cipher'][2]
            }
            info['compression'] = conn_info['compression']
        
        # Add readable issuer information
        issuer_cn = cert.get_issuer().CN if hasattr(cert.get_issuer(), 'CN') else 'Unknown'
        info['issuer_common_name'] = issuer_cn
        
        return info
    
    except Exception as e:
        print(f"Error analyzing certificate: {str(e)}")
        return None

class SecurityAnalyzer:
    def __init__(self):
        # Common weak ciphers and vulnerabilities
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL',
            'EXPORT', 'anon', 'CBC'
        ]
        
        # Known vulnerable TLS/SSL versions
        self.vulnerable_protocols = [
            'SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'
        ]
        
        # Minimum recommended key sizes
        self.min_key_sizes = {
            'RSA': 2048,
            'EC': 256,
            'DSA': 2048
        }

    def check_hsts(self, domain):
        """
        Check if the domain implements HSTS.
        """
        try:
            response = requests.get(f'https://{domain}', timeout=10)
            hsts_header = response.headers.get('Strict-Transport-Security')
            
            if hsts_header:
                # Parse HSTS header
                max_age_match = re.search(r'max-age=(\d+)', hsts_header)
                includes_subdomains = 'includeSubDomains' in hsts_header
                is_preloaded = 'preload' in hsts_header
                
                return {
                    'implemented': True,
                    'max_age': int(max_age_match.group(1)) if max_age_match else None,
                    'includes_subdomains': includes_subdomains,
                    'preload': is_preloaded,
                    'header': hsts_header
                }
            return {
                'implemented': False,
                'reason': 'No HSTS header found'
            }
        except Exception as e:
            return {
                'implemented': False,
                'reason': str(e)
            }

    def check_security_headers(self, domain):
        """
        Check for additional security headers.
        """
        try:
            response = requests.get(f'https://{domain}', timeout=10)
            headers = response.headers
            
            return {
                'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
                'X-XSS-Protection': headers.get('X-XSS-Protection', 'Not Set'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set')
            }
        except Exception as e:
            return {'error': str(e)}

    def check_vulnerabilities(self, domain, cert_info):
        """
        Check for common vulnerabilities.
        """
        vulnerabilities = []
        warnings = []
        
        # Check for weak protocols
        tls_version = cert_info.get('tls_version', '')
        for vuln_proto in self.vulnerable_protocols:
            if vuln_proto in tls_version:
                vulnerabilities.append(f'Using vulnerable protocol: {vuln_proto}')

        # Check for weak ciphers
        cipher_name = cert_info.get('cipher_suite', {}).get('name', '')
        for weak_cipher in self.weak_ciphers:
            if weak_cipher in cipher_name:
                vulnerabilities.append(f'Using weak cipher: {weak_cipher}')

        # Check certificate expiration
        days_until_expiry = (cert_info['valid_until'] - datetime.datetime.now()).days
        if days_until_expiry < 30:
            vulnerabilities.append(f'Certificate expires in {days_until_expiry} days')
        elif days_until_expiry < 90:
            warnings.append(f'Certificate expires in {days_until_expiry} days')

        # Check if self-signed
        if cert_info['issuer'] == cert_info['subject']:
            vulnerabilities.append('Self-signed certificate detected')

        # Check additional security headers
        security_headers = self.check_security_headers(domain)
        if isinstance(security_headers, dict) and 'error' not in security_headers:
            for header, value in security_headers.items():
                if value == 'Not Set':
                    warnings.append(f'Security header {header} not implemented')

        return {
            'vulnerabilities': vulnerabilities,
            'warnings': warnings,
            'security_headers': security_headers
        }

    def analyze_domain_security(self, domain):
        """
        Comprehensive security analysis of a domain.
        """
        print(f"\nAnalyzing security for {domain}...")
        
        # Get basic cert and connection info
        cert_info = analyze_cert_and_connection_info(domain)
        if not cert_info:
            return None

        # Check HSTS
        print("Checking HSTS configuration...")
        hsts_info = self.check_hsts(domain)
        cert_info['hsts'] = hsts_info

        # Check vulnerabilities
        print("Scanning for vulnerabilities...")
        vuln_info = self.check_vulnerabilities(domain, cert_info)
        cert_info['security_scan'] = vuln_info

        return cert_info

def print_security_analysis(cert_info):
    """
    Print comprehensive security analysis.
    """
    if not cert_info:
        print("No security information available")
        return

    print("\nCertificate Information:")
    print("-" * 50)
    print(f"Domain: {cert_info['domain']}")
    print(f"Valid From: {cert_info['valid_from']}")
    print(f"Valid Until: {cert_info['valid_until']}")
    print(f"Issuer Common Name: {cert_info['issuer_common_name']}")
    print(f"Signature Algorithm: {cert_info['signature_algorithm']}")

    print("\nConnection Security:")
    print("-" * 50)
    print(f"TLS Version: {cert_info['tls_version']}")
    print("Cipher Suite:")
    print(f"  - Name: {cert_info['cipher_suite']['name']}")
    print(f"  - Version: {cert_info['cipher_suite']['version']}")
    print(f"  - Bits: {cert_info['cipher_suite']['bits']}")

    print("\nHSTS Information:")
    print("-" * 50)
    hsts = cert_info['hsts']
    if hsts['implemented']:
        print("✅ HSTS is implemented")
        print(f"  - Max Age: {hsts['max_age']} seconds")
        print(f"  - Includes Subdomains: {hsts['includes_subdomains']}")
        print(f"  - Preloaded: {hsts['preload']}")
    else:
        print(f"❌ HSTS is not implemented: {hsts.get('reason', 'No HSTS header')}")

    print("\nSecurity Headers:")
    print("-" * 50)
    security_headers = cert_info['security_scan'].get('security_headers', {})
    if 'error' not in security_headers:
        for header, value in security_headers.items():
            status = "✅" if value != 'Not Set' else "❌"
            print(f"{status} {header}: {value}")

    print("\nVulnerability Scan:")
    print("-" * 50)
    security_scan = cert_info['security_scan']
    
    if not security_scan['vulnerabilities'] and not security_scan['warnings']:
        print("✅ No significant vulnerabilities detected")
    else:
        if security_scan['vulnerabilities']:
            print("\n❌ Vulnerabilities Found:")
            for vuln in security_scan['vulnerabilities']:
                print(f"  - {vuln}")
        
        if security_scan['warnings']:
            print("\n⚠️ Warnings:")
            for warning in security_scan['warnings']:
                print(f"  - {warning}")

    # Certificate expiration reminder
    days_until_expiry = (cert_info['valid_until'] - datetime.datetime.now()).days
    print(f"\nCertificate Status: {days_until_expiry} days until expiration")

def main():
    analyzer = SecurityAnalyzer()
    
    while True:
        domain = input("\nEnter domain to analyze (or 'quit' to exit): ")
        if domain.lower() == 'quit':
            break
            
        try:
            cert_info = analyzer.analyze_domain_security(domain)
            print_security_analysis(cert_info)
        except Exception as e:
            print(f"Error analyzing {domain}: {str(e)}")
        
        print("\n" + "="*70 + "\n")

if __name__ == "__main__":
    main()