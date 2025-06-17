#!/usr/bin/env python3
import argparse
import os
import time
from modules.xss import XSSScanner
from modules.sqli import SQLiScanner
from colorama import init, Fore, Style

init(autoreset=True)

def show_banner():
    print(f"""{Fore.RED}
    ╦ ╦┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌┬┐
    ║║║├┤ ├─┘├─┘│ │└─┐ ├┤  │ 
    ╚╩╝└─┘┴  ┴  └─┘└─┘└─┘ ┴ 
    {Fore.YELLOW}Zeroscope v2.0 (With Payload Delivery)
    {Style.RESET_ALL}""")

def log_usage(action, target):
    with open('usage.log', 'a') as f:
        f.write(f"{time.ctime()} | User: {os.getlogin()} | Action: {action} | Target: {target}\n")

def main():
    show_banner()
    print(f"{Fore.RED}[!] LEGAL WARNING: Unauthorized testing is illegal{Style.RESET_ALL}")
    confirm = input(f"{Fore.YELLOW}[?] Confirm you have permission (y/N): {Style.RESET_ALL}")
    if confirm.lower() != 'y':
        exit()

    parser = argparse.ArgumentParser(description='Zeroscope with Active Exploitation')
    subparsers = parser.add_subparsers(dest='module', required=True)

    # XSS Parser
    xss_parser = subparsers.add_parser('xss', help='XSS Scanning/Exploitation')
    xss_parser.add_argument('-u', '--url', required=True)
    xss_parser.add_argument('--deliver', choices=['cookie', 'keylogger', 'redirect'], help='Deliver exploit payload')
    xss_parser.add_argument('--param', help='Vulnerable parameter name')
    xss_parser.add_argument('-v', '--verbose', action='store_true')
    xss_parser.add_argument('-o', '--output')

    # SQLi Parser
    sqli_parser = subparsers.add_parser('sqli', help='SQL Injection')
    sqli_parser.add_argument('-u', '--url', required=True)
    sqli_parser.add_argument('-v', '--verbose', action='store_true')
    sqli_parser.add_argument('-o', '--output')

    args = parser.parse_args()

    try:
        if args.module == 'xss':
            scanner = XSSScanner()
            if args.deliver:
                if not args.param:
                    print(f"{Fore.RED}[!] Must specify --param for delivery{Style.RESET_ALL}")
                    exit()
                log_usage(f"XSS payload delivery ({args.deliver})", args.url)
                scanner.deliver_payload(args.url, args.param, args.deliver)
            else:
                scanner.scan(args.url, verbose=args.verbose, output_file=args.output)
        
        elif args.module == 'sqli':
            scanner = SQLiScanner()
            scanner.scan(args.url, verbose=args.verbose, output_file=args.output)

    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
