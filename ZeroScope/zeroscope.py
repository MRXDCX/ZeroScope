#!/usr/bin/env python3
import argparse
from modules.xss import XSSScanner
from modules.sqli import SQLiScanner
from colorama import init, Fore, Style
import threading

init(autoreset=True)

# Configurable core
CONFIG = {
    'threads': 5,
    'timeout': 10,
    'user_agents': [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        'Mozilla/5.0 (Linux; Android 10)'
    ]
}

def show_banner():
    print(f"""{Fore.RED}
    ╦ ╦┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌┬┐
    ║║║├┤ ├─┘├─┘│ │└─┐ ├┤  │ 
    ╚╩╝└─┘┴  ┴  └─┘└─┘└─┘ ┴ 
    {Fore.YELLOW}Zeroscope Pro - Advanced Web Security Scanner
    {Style.RESET_ALL}""")

def main():
    show_banner()
    print(f"{Fore.RED}[!] LEGAL DISCLAIMER: Only test authorized systems!{Style.RESET_ALL}")

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='module', required=True)

    # XSS Parser
    xss_parser = subparsers.add_parser('xss')
    xss_parser.add_argument('-u', '--url', required=True)
    xss_parser.add_argument('--crawl', action='store_true', help='Enable crawling')
    xss_parser.add_argument('--blind', metavar='URL', help='Check for blind XSS')
    xss_parser.add_argument('-t', '--threads', type=int, default=CONFIG['threads'])
    xss_parser.add_argument('-v', '--verbose', action='store_true')

    # SQLi Parser
    sqli_parser = subparsers.add_parser('sqli')
    sqli_parser.add_argument('-u', '--url', required=True)
    sqli_parser.add_argument('-v', '--verbose', action='store_true')

    args = parser.parse_args()

    if args.module == 'xss':
        scanner = XSSScanner(
            threads=args.threads,
            config=CONFIG
        )
        scanner.scan(
            args.url, 
            crawl=args.crawl,
            blind_callback=args.blind,
            verbose=args.verbose
        )
    elif args.module == 'sqli':
        SQLiScanner().scan(args.url, verbose=args.verbose)

if __name__ == '__main__':
    main()
