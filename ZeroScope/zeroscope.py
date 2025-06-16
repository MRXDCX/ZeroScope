#!/usr/bin/env python3
import argparse
import os
import sys
import requests
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

class Scanner:
    def __init__(self, url, verbose=False):
        self.target_url = url
        self.verbose = verbose
        self.session = requests.Session()
        self.links = set()
        self.vulnerabilities = []

    def extract_links(self):
        try:
            response = self.session.get(self.target_url)
            soup = BeautifulSoup(response.text, "html.parser")
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = urljoin(self.target_url, href)
                self.links.add(full_url)
            if self.verbose:
                print(f"{Fore.CYAN}[*] Found {len(self.links)} links on page{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Error extracting links: {e}{Style.RESET_ALL}")

    def scan_xss(self):
        payloads = [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '"><script>alert(1)</script>'
        ]
        
        for url in self.links:
            try:
                # Test URL parameters
                parsed = urlparse(url)
                if parsed.query:
                    for payload in payloads:
                        modified = parsed._replace(query=f"{parsed.query}&test={payload}")
                        test_url = modified.geturl()
                        response = self.session.get(test_url)
                        
                        if payload in response.text:
                            self.vulnerabilities.append({
                                'type': 'Reflected XSS',
                                'url': test_url,
                                'parameter': 'test',
                                'payload': payload
                            })
                            print(f"{Fore.GREEN}[+] XSS found in {url}{Style.RESET_ALL}")
                            print(f"Payload: {payload}")
                
                # Test forms
                response = self.session.get(url)
                soup = BeautifulSoup(response.text, "html.parser")
                for form in soup.find_all('form'):
                    form_details = self.analyze_form(form)
                    for payload in payloads:
                        if self.test_form_xss(url, form_details, payload):
                            self.vulnerabilities.append({
                                'type': 'Stored XSS',
                                'url': url,
                                'form': form_details,
                                'payload': payload
                            })
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}[!] Error scanning {url}: {e}{Style.RESET_ALL}")

    def analyze_form(self, form):
        details = {}
        details['action'] = form.get('action')
        details['method'] = form.get('method', 'get').lower()
        details['inputs'] = []
        
        for input_tag in form.find_all('input'):
            input_details = {
                'type': input_tag.get('type', 'text'),
                'name': input_tag.get('name'),
                'value': input_tag.get('value', '')
            }
            details['inputs'].append(input_details)
            
        return details

    def test_form_xss(self, url, form_details, payload):
        target_url = urljoin(url, form_details['action'])
        data = {}
        
        for input in form_details['inputs']:
            if input['type'] == 'text' or input['type'] == 'search':
                data[input['name']] = payload
            else:
                data[input['name']] = input['value']
        
        try:
            if form_details['method'] == 'post':
                response = self.session.post(target_url, data=data)
            else:
                response = self.session.get(target_url, params=data)
            
            return payload in response.text
        except:
            return False

    def generate_report(self):
        print(f"\n{Fore.BLUE}=== Scan Report ==={Style.RESET_ALL}")
        print(f"Target URL: {self.target_url}")
        print(f"Scanned Links: {len(self.links)}")
        print(f"Vulnerabilities Found: {len(self.vulnerabilities)}\n")
        
        for vuln in self.vulnerabilities:
            print(f"{Fore.RED}[!] {vuln['type']}{Style.RESET_ALL}")
            print(f"URL: {vuln['url']}")
            print(f"Payload: {vuln['payload']}")
            if 'parameter' in vuln:
                print(f"Parameter: {vuln['parameter']}")
            print("-" * 50)

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
        sys.exit(0)

def main():
    show_banner()
    show_disclaimer()
    
    parser = argparse.ArgumentParser(description='Zeroscope - Web Application Penetration Testing Tool')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('-o', '--output', help='Output file for report')
    
    args = parser.parse_args()
    
    scanner = Scanner(args.url, args.verbose)
    print(f"{Fore.CYAN}[*] Starting scan on {args.url}{Style.RESET_ALL}")
    
    # Extract all links from the target page
    scanner.extract_links()
    
    # Add the target URL itself to the scan list
    scanner.links.add(args.url)
    
    # Perform XSS scanning
    print(f"{Fore.CYAN}[*] Scanning for XSS vulnerabilities{Style.RESET_ALL}")
    scanner.scan_xss()
    
    # Generate report
    scanner.generate_report()
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(f"Scan Report for {args.url}\n\n")
            for vuln in scanner.vulnerabilities:
                f.write(f"Vulnerability: {vuln['type']}\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Payload: {vuln['payload']}\n\n")
        print(f"{Fore.GREEN}[+] Report saved to {args.output}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Scan completed!{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
