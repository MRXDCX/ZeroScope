#!/usr/bin/env python3
import argparse
from scanner import Scanner
from modules import xss, sqli, blind_xss
from colorama import init, Fore, Style

init(autoreset=True)

def show_banner():
    print(f"""{Fore.RED}
    ╦ ╦┌─┐┌─┐┌─┐┌─┐┌─┐┌─┐┌┬┐
    ║║║├┤ ├─┘├─┘│ │└─┐ ├┤  │ 
    ╚╩╝└─┘┴  ┴  └─┘└─┘└─┘ ┴ 
    {Fore.YELLOW}Advanced Web Application Penetration Testing Tool
    {Style.RESET_ALL}""")

def show_disclaimer():
    print(f"{Fore.RED}[!] LEGAL DISCLAIMER: Only test systems you own or have permission to scan!{Style.RESET_ALL}")
    if input(f"{Fore.YELLOW}[?] Confirm (y/N): {Style.RESET_ALL}").lower() != 'y':
        exit()

def main():
    show_banner()
    show_disclaimer()

    parser = argparse.ArgumentParser(description='Zeroscope with XSStrike enhancements')
    subparsers = parser.add_subparsers(dest='module', required=True)

    # XSS Parser
    xss_parser = subparsers.add_parser('xss', help='Advanced XSS Scanner')
    xss_parser.add_argument('-u', '--url', required=True)
    xss_parser.add_argument('--crawl', action='store_true', help='Crawl site')
    xss_parser.add_argument('--dom', action='store_true', help='Check DOM XSS')
    xss_parser.add_argument('--blind', help='Blind XSS callback URL')
    xss_parser.add_argument('-v', '--verbose', action='store_true')
    xss_parser.add_argument('-o', '--output')

    # SQLi Parser
    sqli_parser = subparsers.add_parser('sqli', help='SQL Injection Scanner')
    sqli_parser.add_argument('-u', '--url', required=True)
    sqli_parser.add_argument('-v', '--verbose', action='store_true')
    sqli_parser.add_argument('-o', '--output')

    args = parser.parse_args()
    scanner = Scanner()

    if args.module == 'xss':
        xss.scan(
            url=args.url,
            crawl=args.crawl,
            check_dom=args.dom,
            blind_callback=args.blind,
            verbose=args.verbose,
            output_file=args.output
        )
    elif args.module == 'sqli':
        sqli.scan(
            url=args.url,
            verbose=args.verbose,
            output_file=args.output
        )

if __name__ == '__main__':
    main()
