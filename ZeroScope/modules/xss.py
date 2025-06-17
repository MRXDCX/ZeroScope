import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
import random

class XSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Zeroscope/1.0'
        }
        self.context_payloads = {
            'html': ['"><svg/onload=alert(1)>', '" autofocus onfocus=alert(1)'],
            'js': ['\';alert(1)//', '{{constructor.constructor(\'alert(1)\')()}}'],
            'attribute': [' onmouseover=alert(1)', ' style=animation-name:alert(1)']
        }

    def scan(self, url, verbose=False, output_file=None):
        try:
            self._test_reflected_xss(url, verbose, output_file)
            self._test_form_xss(url, verbose, output_file)
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")

    def _test_reflected_xss(self, url, verbose, output_file):
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param, values in params.items():
                for ctx, payloads in self.context_payloads.items():
                    for payload in payloads:
                        test_url = self._build_test_url(parsed, param, payload)
                        
                        try:
                            res = self.session.get(test_url)
                            if payload in res.text:
                                self._log_vulnerability(
                                    f"Reflected XSS ({ctx}) in {param}",
                                    test_url,
                                    payload,
                                    output_file
                                )
                        except Exception as e:
                            if verbose:
                                print(f"{Fore.RED}[!] Request failed: {e}{Style.RESET_ALL}")
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] URL parsing error: {e}{Style.RESET_ALL}")

    def _test_form_xss(self, url, verbose, output_file):
        try:
            res = self.session.get(url)
            soup = BeautifulSoup(res.text, 'html.parser')
            
            for form in soup.find_all('form'):
                action = form.get('action', url)
                method = form.get('method', 'get').lower()
                inputs = form.find_all('input')
                
                for ctx, payloads in self.context_payloads.items():
                    for payload in payloads:
                        data = self._build_form_data(inputs, payload)
                        
                        try:
                            if method == 'post':
                                res = self.session.post(urljoin(url, action), data=data)
                            else:
                                res = self.session.get(urljoin(url, action), params=data)
                                
                            if payload in res.text:
                                self._log_vulnerability(
                                    f"Form XSS ({ctx}) in {action}",
                                    url,
                                    payload,
                                    output_file
                                )
                        except Exception as e:
                            if verbose:
                                print(f"{Fore.RED}[!] Form submit failed: {e}{Style.RESET_ALL}")
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] Form parsing error: {e}{Style.RESET_ALL}")

    def _build_test_url(self, parsed, param, payload):
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return parsed._replace(query="&".join(f"{k}={v[0]}" for k,v in params.items())).geturl()

    def _build_form_data(self, inputs, payload):
        data = {}
        for input_tag in inputs:
            name = input_tag.get('name')
            if name:
                data[name] = payload if input_tag.get('type') in ('text', 'search') else input_tag.get('value', '')
        return data

    def _log_vulnerability(self, title, url, payload, output_file):
        msg = f"{Fore.GREEN}[+] {title}{Style.RESET_ALL}\nURL: {url}\nPayload: {payload}\n"
        print(msg)
        
        if output_file:
            with open(output_file, 'a') as f:
                f.write(msg + "\n")
