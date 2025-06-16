#!/usr/bin/env python3
import argparse
import os
import sys
from colorama import init, Fore, Style
from datetime import datetime
from modules import xss, sqli, brute, csrfgen

# Initialize colorama
init(autoreset=True)

# Banner
def show_banner():
    banner = f"""
    {Fore.RED}╦ ╦┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌┬┐
    {Fore.RED}║║║├┤ ├─┘├─┘│ │└─┐ ├┤  │ 
    {Fore.RED}╚╩╝└─┘┴  ┴  └─┘└─┘└─┘ ┴ 
    {Fore.YELLOW}Web Application Penetration Testing Tool
    {Style.RESET_ALL}"""
    print(banner)

# Disclaimer
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

# Setup argument parser
def setup_arg_parser():
    parser = argparse.ArgumentParser(description='Zeroscope - Web Application Penetration Testing Tool')
    
    # Common arguments
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    
    # Module selection
    subparsers = parser.add_subparsers(dest='module', help='Select a module to run')
    
    # XSS module
    xss_parser = subparsers.add_parser('xss', help='XSS Scanner module')
    xss_parser.add_argument('-p', '--payloads', help='Custom XSS payloads file')
    xss_parser.add_argument('-d', '--data', help='POST data parameters (e.g., "user=admin&pass=123")')
    
    # SQLi module
    sqli_parser = subparsers.add_parser('sqli', help='SQL Injection module')
    sqli_parser.add_argument('-p', '--payloads', help='Custom SQLi payloads file')
    sqli_parser.add_argument('-d', '--data', help='POST data parameters')
    sqli_parser.add_argument('-t', '--time-delay', type=int, default=5, 
                           help='Time delay threshold for blind SQLi (seconds)')
    
    # Brute force module
    brute_parser = subparsers.add_parser('brute', help='Login Brute Forcer module')
    brute_parser.add_argument('-U', '--usernames', help='Custom usernames wordlist')
    brute_parser.add_argument('-P', '--passwords', help='Custom passwords wordlist')
    brute_parser.add_argument('-d', '--data', required=True, 
                            help='Login form parameters with {USER} and {PASS} placeholders')
    brute_parser.add_argument('--csrf-field', help='CSRF token field name')
    brute_parser.add_argument('--success-str', required=True, 
                            help='String in response indicating successful login')
    
    # CSRF generator module
    csrf_parser = subparsers.add_parser('csrf', help='CSRF Exploit Generator module')
    csrf_parser.add_argument('-d', '--data', required=True, help='POST data parameters to exploit')
    csrf_parser.add_argument('-a', '--action', help='Form action URL (defaults to target URL)')
    csrf_parser.add_argument('-m', '--method', default='POST', choices=['POST', 'GET'], 
                           help='HTTP method for the form')
    
    return parser

# Main function
def main():
    show_banner()
    show_disclaimer()
    
    parser = setup_arg_parser()
    args = parser.parse_args()
    
    if not args.module:
        parser.print_help()
        sys.exit(1)
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Initialize output file if specified
    output_file = None
    if args.output:
        output_file = open(args.output, 'a')
        output_file.write(f"\nScan started at: {datetime.now()}\n")
        output_file.write(f"Target: {args.url}\nModule: {args.module}\n")
    
    # Execute selected module
    try:
        if args.module == 'xss':
            xss.scan(args.url, args.payloads, args.data, args.verbose, output_file)
        elif args.module == 'sqli':
            sqli.scan(args.url, args.payloads, args.data, args.time_delay, args.verbose, output_file)
        elif args.module == 'brute':
            brute.scan(args.url, args.usernames, args.passwords, args.data, 
                      args.csrf_field, args.success_str, args.verbose, output_file)
        elif args.module == 'csrf':
            csrfgen.generate(args.url, args.data, args.action, args.method, args.verbose, output_file)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")
        if output_file:
            output_file.write(f"Error: {e}\n")
    finally:
        if output_file:
            output_file.close()
    
    print(f"{Fore.GREEN}[+] Scan completed!{Style.RESET_ALL}")

if __name__ == '__main__':
    main()