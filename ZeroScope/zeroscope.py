#!/usr/bin/env python3
"""
ZeroScope Pro - Precision XSS Scanner
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
        self.session.headers = {
            'User-Agent': 'ZeroScope/1.0',
            'Accept': 'text/html,application/xhtml+xml'
        }
        self.vulnerabilities = []

    def test_xss_game_vulnerability(self, url):
        """Specialized test for XSS Game challenges"""
        test_payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            "' onmouseover=alert('XSS')",
            '" onfocus=alert("XSS") autofocus'
        ]
        
        parsed = urlparse(url)
        if 'xss-game.appspot.com' in parsed.netloc:
            # Special handling for XSS Game
            for payload in test_payloads:
                test_url = f"{url}?query={quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=5)
                    if payload in response.text:
                        self.vulnerabilities.append((
                            test_url,
                            "Reflected XSS in query parameter",
                            f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
                        ))
                        return True
                except Exception as e:
                    print(f"{Fore.YELLOW}[!] Error testing {test_url}: {e}{Style.RESET_ALL}")
        return False

    def test_generic_xss(self, url):
        """Test for generic XSS vulnerabilities"""
        test_payloads = [
            ('<script>alert(1)</script>', "Basic script tag"),
            ('" onmouseover=alert(1) ', "Event handler"),
            ('javascript:alert(1)', "JavaScript URI"),
            ('{{constructor.constructor("alert(1)")()}}', "Template injection")
        ]
        
        for payload, description in test_payloads:
            test_url = f"{url}?test={quote(payload)}"
            try:
                response = self.session.get(test_url, timeout=5)
                if payload in response.text:
                    self.vulnerabilities.append((
                        test_url,
                        f"Reflected XSS ({description})",
                        f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
                    ))
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Error testing {test_url}: {e}{Style.RESET_ALL}")

    def scan(self, url):
        """Main scanning function"""
        print(self.banner)
        print(f"{Fore.GREEN}[+] Testing: {url}{Style.RESET_ALL}")
        
        # First try specialized XSS Game test
        if not self.test_xss_game_vulnerability(url):
            # Fall back to generic tests if not XSS Game
            self.test_generic_xss(url)
        
        self.report_results()

    def report_results(self):
        """Display scan results"""
        print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[✓] No vulnerabilities found{Style.RESET_ALL}")
            return
            
        print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:{Style.RESET_ALL}")
        for i, (url, desc, severity) in enumerate(self.vulnerabilities, 1):
            print(f"\n{i}. {severity}{url}{Style.RESET_ALL}")
            print(f"   Type: {desc}")
            print(f"   Severity: {severity.split(':')[0]}")

def main():
    parser = argparse.ArgumentParser(description='ZeroScope XSS Scanner')
    parser.add_argument('xss', help='XSS scanning mode')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    
    args = parser.parse_args()
    
    scanner = ZeroScope()
    scanner.scan(args.url)

if __name__ == "__main__":
    main()
