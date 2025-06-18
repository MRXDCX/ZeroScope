#!/usr/bin/env python3
"""
ZeroScope Pro - Advanced Web Security Scanner
Now with XSS and SQL Injection detection
"""

import argparse
import requests
from urllib.parse import urljoin, quote
import base64

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
                'dom': ["#<script>alert(1)</script>", "#javascript:alert(1)"],
                'html': '<script>alert(1)</script>'
            },
            'sqli': {
                'error_based': ["'", "\"", "' OR 1=1--", "' UNION SELECT null,version()--"],
                'time_based': ["' OR (SELECT sleep(5))--", "' OR BENCHMARK(5000000,MD5('A'))--"]
            }
        }

    def scan_xss(self, url, dom=False):
        """Scan for XSS vulnerabilities"""
        print(f"\n[+] Scanning {url} for {'DOM ' if dom else ''}XSS...")
        if dom:
            for payload in self.payloads['xss']['dom']:
                test_url = urljoin(url, payload)
                try:
                    res = requests.get(test_url, timeout=5)
                    if any(indicator in res.text for indicator in ["<script>", "alert(1)"]):
                        print(f"[!] Vulnerable to DOM XSS: {payload}")
                except Exception as e:
                    print(f"[X] Error: {str(e)}")
        else:
            test_url = urljoin(url, f"?test={quote(self.payloads['xss']['html'])}")
            try:
                res = requests.get(test_url)
                if "<script>alert(1)</script>" in res.text:
                    print("[!] Vulnerable to reflected XSS")
            except Exception as e:
                print(f"[X] Error: {str(e)}")

    def scan_sqli(self, url):
        """Scan for SQL injection vulnerabilities"""
        print(f"\n[+] Scanning {url} for SQLi...")
        
        # Test error-based SQLi
        for payload in self.payloads['sqli']['error_based']:
            test_url = f"{url}?id=1{quote(payload)}"
            try:
                res = requests.get(test_url, timeout=5)
                if any(error in res.text.lower() for error in ["sql", "syntax", "unterminated"]):
                    print(f"[!] Possible SQLi (error-based): {payload}")
            except Exception as e:
                print(f"[X] Error: {str(e)}")
        
        # Test time-based SQLi (will take longer)
        print("[*] Testing time-based SQLi (this may take 10-15 seconds)...")
        for payload in self.payloads['sqli']['time_based']:
            try:
                start = time.time()
                requests.get(f"{url}?id=1{quote(payload)}", timeout=15)
                duration = time.time() - start
                if duration > 5:
                    print(f"[!] Possible SQLi (time-based): {payload} (delay: {duration:.2f}s)")
            except Exception as e:
                print(f"[X] Error: {str(e)}")

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

    # SQLi Scanner
    sqli_parser = subparsers.add_parser('sqli', help='SQL injection scanning')
    sqli_parser.add_argument('-u', '--url', required=True, help='Target URL')

    args = parser.parse_args()

    if args.command == 'xss':
        tool.scan_xss(args.url, args.dom)
    elif args.command == 'sqli':
        tool.scan_sqli(args.url)

if __name__ == "__main__":
    import time  # Required for time-based SQLi
    main()
