#!/usr/bin/env python3
"""
ZeroScope Pro - Enhanced XSS Scanner with Clear Vulnerability Reporting
"""

import argparse
import requests
from urllib.parse import urljoin, urlparse
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
            'reflected': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '"><svg/onload=alert("XSS")>'
            ],
            'dom': [
                '#<script>alert("XSS")</script>',
                '#javascript:alert("XSS")',
                '#" onmouseover=alert("XSS")'
            ]
        }
        self.visited_urls = set()
        self.vulnerabilities = []
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ZeroScope Security Scanner'})

    def should_skip(self, url):
        """Skip non-HTML resources"""
        skip_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.css', '.js']
        return any(url.lower().endswith(ext) for ext in skip_extensions)

    def crawl(self, base_url, depth=0, max_depth=2):
        """Improved crawler with vulnerability detection"""
        if depth > max_depth or base_url in self.visited_urls:
            return

        self.visited_urls.add(base_url)
        
        try:
            print(f"{Fore.WHITE}[*] Testing: {base_url}{Style.RESET_ALL}")
            response = self.session.get(base_url, timeout=10)
            
            # Check for vulnerabilities immediately
            self.test_xss(base_url, response.text)
            
            # Only parse HTML for further crawling
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    url = urljoin(base_url, link['href'])
                    if (urlparse(url).netloc == urlparse(base_url).netloc 
                        and not self.should_skip(url):
                        self.crawl(url, depth+1, max_depth)
                        
        except Exception as e:
            print(f"{Fore.RED}[X] Error testing {base_url}: {str(e)}{Style.RESET_ALL}")

    def test_xss(self, url, response_text):
        """Test for XSS vulnerabilities"""
        # Test Reflected XSS
        for payload in self.payloads['reflected']:
            if payload in response_text:
                self.vulnerabilities.append((
                    url,
                    f"Reflected XSS via payload: {payload}",
                    f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
                ))
        
        # Test DOM XSS indicators
        dom_patterns = [
            r'innerHTML\s*=.+?user.+?input',
            r'document\.write\(.+?user.+?input',
            r'eval\(.+?user.+?input'
        ]
        for pattern in dom_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                self.vulnerabilities.append((
                    url,
                    f"Potential DOM XSS via {pattern}",
                    f"{Fore.YELLOW}MEDIUM{Style.RESET_ALL}"
                ))

    def scan(self, url, crawl=False):
        """Main scanning function"""
        print(self.banner)
        print(f"{Fore.GREEN}[+] Starting scan of {url}{Style.RESET_ALL}")
        
        if crawl:
            print(f"{Fore.CYAN}[*] Crawling enabled (max depth=2){Style.RESET_ALL}")
            self.crawl(url)
        else:
            self.test_xss(url, self.session.get(url).text)
        
        self.report_vulnerabilities()

    def report_vulnerabilities(self):
        """Display found vulnerabilities"""
        print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
        
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}[✓] No vulnerabilities found{Style.RESET_ALL}")
            return
            
        print(f"{Fore.RED}[!] Found {len(self.vulnerabilities)} vulnerabilities:{Style.RESET_ALL}")
        for i, (url, desc, severity) in enumerate(self.vulnerabilities, 1):
            print(f"""
{i}. {Fore.RED}{url}{Style.RESET_ALL}
   {desc}
   Severity: {severity}""")

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
