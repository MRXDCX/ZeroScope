#!/usr/bin/env python3
"""
ZeroScope Pro - Advanced Web Security Scanner
Now with crawling capability
"""

import argparse
import requests
from urllib.parse import urljoin, urlparse, quote
from bs4 import BeautifulSoup
import time

class ZeroScope:
    def __init__(self):
        self.banner = """
███████╗███████╗██████╗ ░█████╗ ░██████╗░█████╗░░█████╗░██████╗░███████╗
╚════██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝
░░███╔═╝█████╗░░██████╔╝██║░░██║╚█████╗░██║░░╚═╝██║░░██║██████╔╝█████╗░░
██╔══╝░░██╔══╝░░██╔══██╗██║░░██║░╚═══██╗██║░░██╗██║░░██║██╔═══╝░██╔══╝░░
███████╗███████╗██║░░██║╚█████╔╝██████╔╝╚█████╔╝╚█████╔╝██║░░░░░███████╗
╚══════╝╚══════╝╚═╝░░╚═╝░╚════╝░╚═════╝░░╚════╝░░╚════╝░╚═╝░░░░░╚══════╝
"""
        self.payloads = {
            'xss': {
                'dom': ["#<script>alert('XSS')</script>", "#javascript:alert(1)"],
                'reflected': "<script>alert('XSS')</script>",
                'stored': "<svg onload=alert('XSS')>"
            },
            'sqli': {
                'error_based': ["'", "\"", "' OR 1=1--"],
                'time_based': ["' OR (SELECT sleep(5))--"]
            }
        }
        self.visited_urls = set()
        self.max_depth = 2
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ZeroScope Security Scanner'})

    def crawl(self, base_url, depth=0):
        """Recursive website crawler"""
        if depth > self.max_depth or base_url in self.visited_urls:
            return []

        self.visited_urls.add(base_url)
        print(f"[*] Crawling: {base_url}")
        
        try:
            response = self.session.get(base_url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            urls = []
            
            for link in soup.find_all('a', href=True):
                url = urljoin(base_url, link['href'])
                if urlparse(url).netloc == urlparse(base_url).netloc:  # Same domain
                    urls.append(url)
                    if url not in self.visited_urls:
                        urls.extend(self.crawl(url, depth+1))
            
            return list(set(urls))  # Remove duplicates
        except Exception as e:
            print(f"[X] Crawl error: {str(e)}")
            return []

    def scan_xss(self, url, dom=False, crawl=False):
        """Scan for XSS vulnerabilities"""
        targets = [url]
        
        if crawl:
            print("[*] Starting crawl...")
            targets.extend(self.crawl(url))
            print(f"[+] Found {len(targets)} unique URLs to test")
        
        for target in targets:
            print(f"\n[+] Testing: {target}")
            
            if dom:
                for payload in self.payloads['xss']['dom']:
                    test_url = urljoin(target, payload)
                    try:
                        res = self.session.get(test_url)
                        if "XSS" in res.text or "alert(1)" in res.text:
                            print(f"[!] DOM XSS found: {test_url}")
                    except Exception as e:
                        print(f"[X] Error: {str(e)}")
            else:
                test_url = f"{target}?test={quote(self.payloads['xss']['reflected'])}"
                try:
                    res = self.session.get(test_url)
                    if self.payloads['xss']['reflected'] in res.text:
                        print(f"[!] Reflected XSS found: {test_url}")
                except Exception as e:
                    print(f"[X] Error: {str(e)}")

    def scan_sqli(self, url):
        """SQL injection scanning (existing implementation)"""
        # ... [Previous SQLi code remains unchanged] ...

def main():
    tool = ZeroScope()
    print(tool.banner)
    print("ZeroScope Pro - Web Security Scanner\n[!] LEGAL DISCLAIMER: Only test authorized systems!\n")

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', required=True)

    # XSS Scanner
    xss_parser = subparsers.add_parser('xss', help='XSS scanning')
    xss_parser.add_argument('-u', '--url', required=True, help='Target URL')
    xss_parser.add_argument('--dom', action='store_true', help='Scan for DOM XSS')
    xss_parser.add_argument('--crawl', action='store_true', help='Crawl the site')

    # SQLi Scanner
    sqli_parser = subparsers.add_parser('sqli', help='SQL injection scanning')
    sqli_parser.add_argument('-u', '--url', required=True, help='Target URL')

    args = parser.parse_args()

    if args.command == 'xss':
        tool.scan_xss(args.url, args.dom, args.crawl)
    elif args.command == 'sqli':
        tool.scan_sqli(args.url)

if __name__ == "__main__":
    main()
