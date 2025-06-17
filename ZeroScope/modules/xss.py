import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
import random

class XSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Zeroscope/1.0'}
        self.payloads = [
            '<script>alert(1)</script>',
            '" onmouseover=alert(1)',
            '<img src=x onerror=alert(1)>',
            'javascript:alert(1)'
        ]

    def scan(self, url, verbose=False, output_file=None):
        """Passive XSS scanning only"""
        try:
            # Test URL parameters
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.payloads:
                    test_url = self._build_test_url(parsed, param, payload)
                    
                    try:
                        res = self.session.get(test_url)
                        if payload in res.text:
                            self._log_vulnerability(
                                f"Reflected XSS in {param}",
                                test_url,
                                payload,
                                output_file
                            )
                    except Exception as e:
                        if verbose:
                            print(f"{Fore.RED}[!] Test failed: {e}{Style.RESET_ALL}")

            # Test forms
            self._test_forms(url, verbose, output_file)
            
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")

    def _build_test_url(self, parsed, param, payload):
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return parsed._replace(query="&".join(f"{k}={v[0]}" for k,v in params.items())).geturl()

    def _test_forms(self, url, verbose, output_file):
        try:
            res = self.session.get(url)
            soup = BeautifulSoup(res.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', url)
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                
                for payload in self.payloads:
                    data = {}
                    for tag in inputs:
                        name = tag.get('name')
                        if name:
                            data[name] = payload if tag.get('type') in ('text', 'search') else tag.get('value', '')
                    
                    try:
                        if method == 'post':
                            res = self.session.post(urljoin(url, action), data=data)
                        else:
                            res = self.session.get(urljoin(url, action), params=data)
                            
                        if payload in res.text:
                            self._log_vulnerability(
                                f"Form XSS at {action}",
                                url,
                                payload,
                                output_file
                            )
                    except Exception as e:
                        if verbose:
                            print(f"{Fore.RED}[!] Form test failed: {e}{Style.RESET_ALL}")
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] Form scan error: {e}{Style.RESET_ALL}")

    def _log_vulnerability(self, title, url, payload, output_file):
        msg = f"{Fore.GREEN}[+] {title}{Style.RESET_ALL}\nURL: {url}\nPayload: {payload}\n"
        print(msg)
        if output_file:
            with open(output_file, 'a') as f:
                f.write(msg + "\n")
