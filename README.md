Zeroscope Pro Commands
Core Syntax
bash
python3 zeroscope.py [module] [options]
XSS Scanning Module
Basic Scanning
bash
# Scan single URL for XSS
python3 zeroscope.py xss -u "http://example.com/search?q=test"

# Verbose mode (show errors)
python3 zeroscope.py xss -u "http://example.com" -v
Advanced Features
bash
# Crawl entire site (multi-threaded)
python3 zeroscope.py xss -u "http://example.com" --crawl

# Set thread count (default: 5)
python3 zeroscope.py xss -u "http://example.com" --crawl -t 10

# Check for Blind XSS (with callback URL)
python3 zeroscope.py xss -u "http://example.com/feedback" --blind http://your-server.com

# DOM XSS detection only
python3 zeroscope.py xss -u "http://example.com" --dom
SQL Injection Module
bash
# Basic SQLi detection
python3 zeroscope.py sqli -u "http://example.com/product?id=1"

# Verbose mode
python3 zeroscope.py sqli -u "http://example.com" -v
WAF Handling
bash
# Auto-detect and evade WAF (built into all scans)
python3 zeroscope.py xss -u "http://waf-protected-site.com" -v

# Manual WAF testing
python3 zeroscope.py xss -u "http://example.com" --test-waf
Configuration Options
bash
# Use custom config file
python3 zeroscope.py xss -u "http://example.com" --config myconfig.json

# Override default user-agent
python3 zeroscope.py xss -u "http://example.com" --user-agent "My Custom Agent"
Output Control
bash
# Save results to file
python3 zeroscope.py xss -u "http://example.com" -o results.txt

# JSON output format
python3 zeroscope.py xss -u "http://example.com" --json
Special Modes
bash
# Passive mode (no active payloads)
python3 zeroscope.py xss -u "http://example.com" --passive

# Stealth mode (random delays, IP rotation)
python3 zeroscope.py xss -u "http://example.com" --stealth
Help System
bash
# Show all options
python3 zeroscope.py --help

# Module-specific help
python3 zeroscope.py xss --help
python3 zeroscope.py sqli --help
Payload Management
bash
# Use custom payload file
python3 zeroscope.py xss -u "http://example.com" --payloads mypayloads.txt

# List built-in payloads
python3 zeroscope.py xss --list-payloads
Key Features Summary:
XSS Detection: Reflected, DOM, and Blind

SQLi Detection: Error-based and Time-based

WAF Evasion: Automatic detection and bypass

Multi-threading: Fast crawling/scans

Context Awareness: HTML/JS/Attribute-specific payloads

Flexible Output: CLI, JSON, file logging

Example Workflow:
Quick test:

bash
python3 zeroscope.py xss -u "http://testphp.vulnweb.com/search.php?test=1" -v
Full site audit:

bash
python3 zeroscope.py xss -u "http://example.com" --crawl -t 8 -o report.json
Blind XSS setup:

bash
python3 zeroscope.py xss -u "http://example.com/contact" --blind http://your-callback-server.com
