#!/usr/bin/env python3
import argparse
from modules.xss import XSSScanner
from modules.sqli import SQLiScanner
from colorama import init, Fore, Style

init(autoreset=True)

def show_banner():
    print(f"""{Fore.RED}
    ╦ ╦┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌┬┐
    ║║║├┤ ├─┘├─┘│ │└─┐ ├┤  │ 
    ╚╩╝└─┘┴  ┴  └─┘└─┘└─┘ ┴ 
    {Fore.YELLOW}Zeroscope Web Application Scanner
    {Style.RESET_ALL}""")

def show_disclaimer():
    print(f"{Fore.RED}[!] LEGAL DISCLAIMER: Only test authorized systems!{Style.RESET_ALL}")
    if input(f"{Fore.YELLOW}[?] Confirm (y/N): {Style.RESET_ALL}").lower() != 'y':
        exit()

def main():
    show_banner()
    show_disclaimer()

    parser = argparse.ArgumentParser(description='Zeroscope Scanner')
    subparsers = parser.add_subparsers(dest='module', required=True)

    # XSS Parser
    xss_parser = subparsers.add_parser('xss', help='XSS Scanning')
    xss_parser.add_argument('-u', '--url', required=True)
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
            scanner.scan(args.url, verbose=args.verbose, output_file=args.output)
        elif args.module == 'sqli':
            scanner = SQLiScanner()
            scanner.scan(args.url, verbose=args.verbose, output_file=args.output)
    except Exception as e:
        print(f"{Fore.RED}[!] Error: {e}{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
