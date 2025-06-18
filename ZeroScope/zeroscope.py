#!/usr/bin/env python3
"""
ZeroScope Pro - Enhanced XSS Scanner (Parameter Testing Edition)
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

    def test_parameter_xss(self, url):
        """Test all parameters for XSS vulnerabilities"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # If no parameters, test the base URL
            self.test_url_response(url)
            return
            
        for param in params:
            for payload in self.payloads['reflected']:
                # Create test URL with injected payload
                test_params = params.copy()
                test_params[param] = [payload]
                test_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=test_query))
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    if payload in response.text:
                        self.vulnerabilities.append((
                            test_url,
                            f"Reflected XSS in parameter: {param}",
                            f"{Fore.RED}CRITICAL{Style.RESET_ALL}"
                        ))
                except Exception as e:
                    print(f"{Fore.RED}[X] Error testing {test_url}: {str(e)}{Style.RESET_ALL}")

    def test_url_response(self, url):
        """Test a URL for DOM XSS patterns"""
        try:
            response = self.session.get(url, timeout=10)
            # Test DOM XSS indicators
            dom_patterns = [
                r'innerHTML\s*=.+?user.+?input',
                r'document\.write\(.+?user.+?input',
                r'eval\(.+?user.+?input'
            ]
            for pattern in dom_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self.vulnerabilities.append((
                        url,
                        f"Potential DOM XSS via {pattern}",
                        f"{Fore.YELLOW}MEDIUM{Style.RESET_ALL}"
                    ))
        except Exception as e:
            print(f"{Fore.RED}[X] Error testing {url}: {str(e)}{Style.RESET_ALL}")

    def crawl(self, base_url, depth=0, max_depth=2):
        """Improved crawler with parameter testing"""
        if depth > max_depth or base_url in self.visited_urls:
            return

        self.visited_urls.add(base_url)
        
        try:
            print(f"{Fore.WHITE}[*] Testing: {base_url}{Style.RESET_ALL}")
            
            # First test all parameters
            self.test_parameter_xss(base_url)
            
            # Then test the base URL for DOM patterns
            self.test_url_response(base_url)
            
            # Only parse HTML for further crawling
            response = self.session.get(base_url, timeout=10)
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a', href=True):
                    url = urljoin(base_url, link['href'])
                    if (urlparse(url).netloc == urlparse(base_url).netloc and 
                        not self.should_skip(url)):
                        self.crawl(url, depth+1, max_depth)
                        
        except Exception as e:
            print(f"{Fore.RED}[X] Error testing {base_url}: {str(e)}{Style.RESET_ALL}")

    def scan(self, url, crawl=False):
        """Main scanning function"""
        print(self.banner)
        print(f"{Fore.GREEN}[+] Starting scan of {url}{Style.RESET_ALL}")
        
        if crawl:
            print(f"{Fore.CYAN}[*] Crawling enabled (max depth=2){Style.RESET_ALL}")
            self.crawl(url)
        else:
            self.test_parameter_xss(url)
            self.test_url_response(url)
        
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
