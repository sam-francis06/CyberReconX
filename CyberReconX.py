import whois
import requests
import dns.resolver
import socket
import json
import time
import pyfiglet
import ssl
from colorama import Fore, Back, Style, init
from requests.exceptions import RequestException
import concurrent.futures

# Initialize colorama
init(autoreset=True)

def print_banner():
    banner = pyfiglet.figlet_format("CyberReconX")
    print(Fore.GREEN + banner + Fore.WHITE + "Advanced Cyber Recon Tool | By Sam")

def whois_lookup(domain):
    print(Fore.CYAN + f"\n[+] Performing WHOIS lookup for {domain}...")
    try:
        w = whois.whois(domain)
        print(json.dumps(w.__dict__, indent=4))
    except Exception as e:
        print(Fore.RED + f"Error during WHOIS lookup: {e}")

def dns_lookup(domain):
    print(Fore.CYAN + f"\n[+] Fetching DNS records for {domain}...")
    record_types = ['A', 'MX', 'TXT', 'CNAME', 'NS', 'SOA']
    
    for record_type in record_types:
        try:
            print(f"{record_type} records:")
            answers = dns.resolver.resolve(domain, record_type)
            for rdata in answers:
                print(f" - {rdata.to_text()}")
        except dns.resolver.NoAnswer:
            print(f" - No {record_type} records found")
        except dns.resolver.NXDOMAIN:
            print(Fore.RED + f" - Domain does not exist")
            break
        except Exception as e:
            print(Fore.RED + f" - Error retrieving {record_type} records: {e}")

def ip_geolocation(ip):
    print(Fore.CYAN + f"\n[+] Performing IP Geolocation for {ip}...")
    try:
        url = f"https://ipinfo.io/{ip}/json"
        response = requests.get(url, timeout=10)
        geo_info = response.json()
        print(json.dumps(geo_info, indent=4))
    except RequestException as e:
        print(Fore.RED + f"Error: {e}")

def reverse_dns(ip):
    print(Fore.CYAN + f"\n[+] Performing Reverse DNS lookup for {ip}...")
    try:
        host = socket.gethostbyaddr(ip)
        print(f"Reverse DNS: {host[0]}")
    except socket.herror:
        print(Fore.RED + "No PTR record found.")
    except Exception as e:
        print(Fore.RED + f"Error: {e}")

def ssl_certificate(domain):
    print(Fore.CYAN + f"\n[+] Fetching SSL/TLS certificate for {domain}...")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
        print(Fore.GREEN + "Certificate Information:")
        # Process and display subject information
        subject = dict(x[0] for x in cert['subject'])
        print(f"Subject: {subject.get('commonName', 'N/A')}")
        
        # Process and display issuer information
        issuer = dict(x[0] for x in cert['issuer'])
        print(f"Issuer: {issuer.get('commonName', 'N/A')}")
        
        print(f"Valid from: {cert['notBefore']}")
        print(f"Valid until: {cert['notAfter']}")
        
        if 'subjectAltName' in cert:
            print("Subject Alternative Names:")
            for san_type, san_value in cert['subjectAltName']:
                print(f" - {san_type}: {san_value}")
    except Exception as e:
        print(Fore.RED + f"Error fetching SSL certificate: {e}")

def subdomain_enumeration(domain):
    print(Fore.CYAN + f"\n[+] Enumerating subdomains for {domain}...")
    try:
        response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if response.status_code == 200 and response.text:
            subdomains = response.text.splitlines()
            if subdomains and not subdomains[0].startswith("error"):
                print(Fore.GREEN + f"Found {len(subdomains)} subdomains:")
                for sub in subdomains:
                    print(f" - {sub}")
            else:
                print(Fore.YELLOW + "No subdomains found or API limit reached.")
        else:
            print(Fore.RED + f"Failed to enumerate subdomains. Status code: {response.status_code}")
    except RequestException as e:
        print(Fore.RED + f"Error: {e}")

def port_scan(target, common_only=True):
    print(Fore.CYAN + f"\n[+] Performing quick port scan on {target}...")
    
    if common_only:
        ports = [21, 22, 23, 25, 53, 80, 110, 115, 135, 139, 143, 194, 443, 445, 1433, 3306, 3389, 5632, 5900, 8080]
    else:
        ports = range(1, 1001)
    
    open_ports = []
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_port = {executor.submit(check_port, target, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            try:
                is_open = future.result()
                if is_open:
                    service = get_service_name(port)
                    open_ports.append((port, service))
                    print(Fore.GREEN + f" - Port {port} is open: {service}")
            except Exception as e:
                print(Fore.RED + f" - Error scanning port {port}: {e}")
    
    if not open_ports:
        print(Fore.YELLOW + " - No open ports found.")
    
    return open_ports

def check_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    result = sock.connect_ex((target, port))
    sock.close()
    return result == 0

def get_service_name(port):
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        115: "SFTP",
        135: "MSRPC",
        139: "NetBIOS",
        143: "IMAP",
        194: "IRC",
        443: "HTTPS",
        445: "SMB",
        1433: "MSSQL",
        3306: "MySQL",
        3389: "RDP",
        5632: "PCAnywhere",
        5900: "VNC",
        8080: "HTTP-Proxy"
    }
    return common_ports.get(port, "Unknown")

def http_headers(url):
    print(Fore.CYAN + f"\n[+] Analyzing HTTP headers for {url}...")
    if not url.startswith('http'):
        url = f"http://{url}"
    
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        print(Fore.GREEN + "HTTP Headers:")
        for header, value in response.headers.items():
            print(f" - {header}: {value}")
        
        # Check for security headers
        security_headers = {
            'Strict-Transport-Security': 'Missing HSTS header',
            'Content-Security-Policy': 'Missing CSP header',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options header',
            'X-Frame-Options': 'Missing X-Frame-Options header',
            'X-XSS-Protection': 'Missing XSS Protection header'
        }
        
        print(Fore.YELLOW + "\nSecurity Headers Analysis:")
        for header, message in security_headers.items():
            if header in response.headers:
                print(Fore.GREEN + f" - {header}: Present")
            else:
                print(Fore.RED + f" - {message}")
        
    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"Error: {e}")

def print_section_divider():
    """Print a divider line to separate output sections."""
    terminal_width = 80  # Default width
    try:
        # Try to get the actual terminal width if possible
        import os
        terminal_size = os.get_terminal_size()
        terminal_width = terminal_size.columns
    except:
        pass
    
    print(Fore.BLUE + "-" * terminal_width)

def main():
    print_banner()
    
    while True:
        print_section_divider()
        print(Fore.YELLOW + "\nChoose an option:")
        print(Fore.YELLOW + "1. Domain Recon")
        print(Fore.YELLOW + "2. IP Recon")
        print(Fore.YELLOW + "3. Subdomain Enumeration")
        print(Fore.YELLOW + "4. SSL/TLS Info")
        print(Fore.YELLOW + "5. Quick Port Scan")
        print(Fore.YELLOW + "6. HTTP Headers Analysis")
        print(Fore.YELLOW + "7. Full Reconnaissance")
        print(Fore.YELLOW + "8. Exit")
        print_section_divider()

        choice = input(Fore.YELLOW + "Enter your choice: ")

        if choice == '1':
            domain = input(Fore.CYAN + "Enter domain: ")
            whois_lookup(domain)
            print_section_divider()
            dns_lookup(domain)
            print_section_divider()
            print_banner()
        elif choice == '2':
            ip = input(Fore.CYAN + "Enter IP: ")
            ip_geolocation(ip)
            print_section_divider()
            reverse_dns(ip)
            print_section_divider()
            print_banner()
        elif choice == '3':
            domain = input(Fore.CYAN + "Enter domain: ")
            subdomain_enumeration(domain)
            print_section_divider()
            print_banner()
        elif choice == '4':
            domain = input(Fore.CYAN + "Enter domain: ")
            ssl_certificate(domain)
            print_section_divider()
            print_banner()
        elif choice == '5':
            target = input(Fore.CYAN + "Enter domain or IP: ")
            scan_type = input(Fore.CYAN + "Scan common ports only? (y/n): ").lower()
            common_only = scan_type != 'n'
            port_scan(target, common_only)
            print_section_divider()
            print_banner()
        elif choice == '6':
            url = input(Fore.CYAN + "Enter URL: ")
            http_headers(url)
            print_section_divider()
            print_banner()
        elif choice == '7':
            target = input(Fore.CYAN + "Enter domain: ")
            print(Fore.GREEN + f"\n[+] Starting full reconnaissance for {target}...")
            print_section_divider()
            
            # Resolve IP if domain
            try:
                ip = socket.gethostbyname(target)
                print(Fore.GREEN + f"\n[+] Resolved {target} to IP: {ip}")
            except:
                print(Fore.RED + f"\n[!] Could not resolve {target} to IP")
                ip = target
            
            whois_lookup(target)
            print_section_divider()
            dns_lookup(target)
            print_section_divider()
            ip_geolocation(ip)
            print_section_divider()
            subdomain_enumeration(target)
            print_section_divider()
            
            try:
                ssl_certificate(target)
                print_section_divider()
            except:
                print(Fore.RED + f"\n[!] SSL certificate retrieval failed for {target}")
                print_section_divider()
            
            port_scan(ip)
            print_section_divider()
            http_headers(target)
            
            print_section_divider()
            print(Fore.GREEN + f"\n[+] Full reconnaissance for {target} completed!")
            print_section_divider()
            print_banner()
            
        elif choice == '8':
            print(Fore.GREEN + "Exiting CyberReconX...")
            time.sleep(1)
            break
        else:
            print(Fore.RED + "Invalid choice. Please select a valid option.")
            print_section_divider()
            print_banner()

if __name__ == "__main__":
    main()
