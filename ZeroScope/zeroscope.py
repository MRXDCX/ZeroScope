#!/usr/bin/env python3
"""
ZeroScope Pro - Complete XSS Scanner (DOM + Reflected)
"""

import argparse
import requests
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from bs4 import BeautifulSoup
import re
from colorama import Fore, Style

class ZeroScope:
    def __init__(self):
        self.banner = f"""{Fore.CYAN}
███████╗███████╗██████╗ ░█████╗ ░██████╗░█████╗░░█████╗░██████╗░███████╗
╚════██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝
░░███╔═╝█████╗░░██████╔╝██║░░██║╚█████╗░██║░░╚═╝██║░░██║██████╔╝█████╗░░
██╔══╝░░██╔══╝░░██╔══██╗██║░░██║░╚═══██╗██║░░██╗██║░░██║██╔═══╝░██╔══╝░░
███████╗███████╗██║░░██║╚█████╔╝██████╔╝╚█████╔╝╚█████╔╝██║░░░░░███████╗
╚══════╝╚══════╝╚═╝░░╚═╝░╚════╝░╚═════╝░░╚════╝░░╚════╝░╚═╝░░░░░╚══════╝
{Style.RESET_ALL}"""
        self.payloads = {
            'dom': [
                "#<script>alert('ZeroScope_XSS')</script>",
                "#javascript:alert('ZeroScope_XSS')",
                "#\" onmouseover='alert(`ZeroScope_XSS`)'"
            ],
            'reflected': [
                '<script>alert("ZeroScope_XSS")</script>',
                '<img src=x onerror=alert("ZeroScope_XSS")>',
                '"><svg/onload=alert("ZeroScope_XSS")>'
            ]
        }
        self.visited_urls = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZeroScope Security Scanner',
            'Accept': 'text/html,application/xhtml+xml'
        })

    def test_dom_xss(self, url):
        """Test for DOM XSS using hash payloads"""
        for payload in self.payloads['dom']:
            test_url = f"{url}{payload}"
            try:
                response = self.session.get(test_url, timeout=10)
                
                # Check both response text and if payload executes
                if ("ZeroScope_XSS" in response.text or 
                    "alert(" in response.text):
                    self.vulnerabilities.append((
                        test_url,
                        f"DOM XSS via hash payload",
                        f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
                    ))
            except Exception as e:
                print(f"{Fore.RED}[X] Error testing {test_url}: {str(e)}{Style.RESET_ALL}")

    def test_reflected_xss(self, url):
        """Test for reflected XSS in parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # If no parameters, test base URL with payload
            for payload in self.payloads['reflected']:
                test_url = f"{url}?test={quote(payload)}"
                try:
                    response = self.session.get(test_url)
                    if payload in response.text:
                        self.vulnerabilities.append((
                            test_url,
                            f"Reflected XSS (parameter: test)",
                            f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
                        ))
                except Exception as e:
                    print(f"{Fore.RED}[X] Error testing {test_url}: {str(e)}{Style.RESET_ALL}")
            return
            
        for param in params:
            for payload in self.payloads['reflected']:
                test_params = params.copy()
                test_params[param] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                
                try:
                    response = self.session.get(test_url)
                    if payload in response.text:
                        self.vulnerabilities.append((
                            test_url,
                            f"Reflected XSS (parameter: {param})",
                            f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
                        ))
                except Exception as e:
                    print(f"{Fore.RED}[X] Error testing {test_url}: {str(e)}{Style.RESET_ALL}")

    def crawl(self, base_url, depth=0, max_depth=2):
        """Crawl website and test all pages"""
        if depth > max_depth or base_url in self.visited_urls:
            return

        self.visited_urls.add(base_url)
        print(f"{Fore.WHITE}[*] Testing: {base_url}{Style.RESET_ALL}")
        
        # Test both DOM and reflected XSS
        self.test_dom_xss(base_url)
        self.test_reflected_xss(base_url)
        
        try:
            response = self.session.get(base_url, timeout=10)
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    url = urljoin(base_url, link['href'])
                    if (urlparse(url).netloc == urlparse(base_url).netloc and
                        not any(url.endswith(ext) for ext in ['.jpg', '.png', '.css', '.js'])):
                        self.crawl(url, depth+1, max_depth)
        except Exception as e:
            print(f"{Fore.RED}[X] Error crawling {base_url}: {str(e)}{Style.RESET_ALL}")

    def scan(self, url, crawl=False):
        """Main scanning function"""
        print(self.banner)
        print(f"{Fore.GREEN}[+] Starting scan of {url}{Style.RESET_ALL}")
        
        if crawl:
            print(f"{Fore.CYAN}[*] Crawling enabled (max depth=2){Style.RESET_ALL}")
            self.crawl(url)
        else:
            self.test_dom_xss(url)
            self.test_reflected_xss(url)
        
        self.report_vulnerabilities()

    def report_vulnerabilities(self):
        """Display found vulnerabilities"""
        print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[✓] No vulnerabilities found{Style.RESET_ALL}")
            return
            
        print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:{Style.RESET_ALL}")
        for i, (url, desc, severity) in enumerate(self.vulnerabilities, 1):
            print(f"\n{i}. {severity}{url}{Style.RESET_ALL}")
            print(f"   {desc}")
            print(f"   {severity}Severity: {severity.split(':')[0]}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='ZeroScope Pro XSS Scanner')
    parser.add_argument('xss', help='XSS scanning mode')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--crawl', action='store_true', help='Enable crawling')
    
    args = parser.parse_args()
    
    scanner = ZeroScope()
    scanner.scan(args.url, args.crawl)

if __name__ == "__main__":
    main()
