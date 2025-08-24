import requests, sys, re, os, json
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
# class XSSScanner:
#     def __init__(self, base_url):
#         self.base_url = base_url
#         self.session = requests.Session()
#         self.visited = set() 
#         self.payloads = [
#             "<script>alert('XSS')</script>",
#             "<img src=x onerror=alert('XSS')>",
#             "<svg/onload=alert('XSS')>"
#         ]
#         self.vulns = []
#     def is_reflected(self, resp, payload):
#         return payload in resp

#     def test_payload(self, url, method, data, field, payload):
#         try:
#             resp = self.session.post(url, data) if method=="post" else self.session.get(url, params=data)
#             if self.is_reflected(resp.text, payload):
#                 self.vulns.append((url, field, payload, method.upper()))
#         except: pass

#     def test_inputs(self, url):
#         try:
#             r = self.session.get(url, timeout=5)
#             soup = BeautifulSoup(r.text, "html.parser")

            
#             for form in soup.find_all("form"):
#                 action = urljoin(url, form.get("action") or url)
#                 method = form.get("method","get").lower()
#                 inputs = {i.get("name"):"test" for i in form.find_all(["input","textarea"]) if i.get("name")}
#                 for field in inputs:
#                     for p in self.payloads:
#                         data = inputs.copy(); data[field] = p
#                         self.test_payload(action, method, data, field, p)

#             params = parse_qs(urlparse(url).query)
#             for field in params:
#                 for p in self.payloads:
#                     test_params = params.copy(); test_params[field] = p
#                     self.test_payload(url, "get", test_params, field, p)

#         except: pass


#     def crawl(self, url, depth=0):
#         if depth>2 or url in self.visited: return
#         self.visited.add(url)
#         self.test_inputs(url)
#         try:
#             soup = BeautifulSoup(self.session.get(url).text,"html.parser")
#             for link in soup.find_all("a", href=True):
#                 next_url = urljoin(url, link["href"])
#                 if urlparse(next_url).netloc == urlparse(self.base_url).netloc:
#                     self.crawl(next_url, depth+1)
#         except: pass

  
#     def report(self):
#         print("\n=== XSS Report ===")
#         if not self.vulns:
#             print("No XSS found.")
#         for url, field, payload, method in self.vulns:
#             print(f"[VULNERABLE] {url} | {field} | {method} | payload={payload}")

# if __name__=="__main__":
#     if len(sys.argv) < 2:
#         exit("python xss.py {url}")
#     target = sys.argv[1]
#     try:
#         if requests.get(target, timeout=5).status_code != 200:
#          exit("Website unreachable.")
#     except:
#          exit("Error accessing site.")

#     scan = XSSScanner(target)
#     scan.crawl(target)
#     scan.report()

# build the web crawler object
# class WebCrawler:

#     # create three variables: start_url, max_depth, list of visited urls
#     def __init__(self, start_url, max_depth=2):
#         self.start_url = start_url
#         self.max_depth = max_depth
#         self.visited = set()



# # create a function to make sure that the primary url is valid
# def is_successful(self):

#     try:
#         response = requests.get(self.start_url, timeout=20) # request the page info 
#         response.raise_for_status() # raises exception when not a 2xx response
#         if response.status_code == 200: # check if the status code is 200, a.k.a successful
#             return True
        
#         else: # if not, print the error with the status code
#             print(f"The crawling could not being becasue of unsuccessful request with the status code of {response.status_code}.")

#     except requests.HTTPError as e: # if HTTPS Error occured, print the error message
#         print(f"HTTP Error occurred: {e}")

#     except Exception as e: # if any other error occured, print the error message
#         print(f"An error occurred: {e}")
# # create a function to get the links
# def process_page(self, url, depth):

#     # apply depth threshold
#     if depth > self.max_depth or url in self.visited:
#         return set(), '' # return empty set and string

#     self.visited.add(url) # add the visited url to the set
#     links = set() # create a set to store the collected links
#     content = '' # create a variable to store the content extracted

#     try:
#         r = requests.get(url, timeout=10) # request the content of a url
#         r.raise_for_status() # check if the request status is successful
#         soup = BeautifulSoup(r.text, 'html.parser') # parse the content of the collected HTML
        
#         # Extract the links
#         anchors = soup.find_all('a') # find all the anchors

#         for anchor in anchors: # merge the anchor with the starting url
#             link = requests.compat.urljoin(url, anchor.get('href')) # get the link and join it with the starting url
#             links.add(link) # add the link to the previously created set
        
#         # Extract the content from the url
#         content = ' '.join([par.text for par in soup.find_all('p')]) # get all the text
#         content =  re.sub(r'[\n\r\t]', '', content) # remove the sequence characters

#     except requests.RequestException: # if the request encounters an error, pass
#         pass

#     return links, content # return the set of the collected links and the contet of the current url
# # crawl the web within the depth determined
# def crawl(self):
    
#     if self.is_successful(): # check if the requesting the starting url info is valid to continue crawling
        
#         urls_content = {} # create a dictionary to store the links as keys and contents as values
#         urls_to_crawl = {self.start_url} # start crawling from the initial url

#         # crawl the web within the depth determined
#         for depth in range(self.max_depth + 1):

#             new_urls = set() # create a set to store the internal new urls

#             for url in urls_to_crawl:  # crawl through the urls

#                 if url not in self.visited: # check and make sure that the url is not crawled before
#                     links, content = self.process_page(url, depth) # return the links and content of the crawled url
#                     urls_content[url] = content # add the url as a key and content as a value to the disctionary created previously
#                     new_urls.update(links) # add the internal links to the previously created set

#             urls_to_crawl = new_urls # change the urls to crawl list to crawl through the internal links

#         # create a folder to store the crawled websites
#         current_dir = os.getcwd() # get the current working directory
#         folder_dir = os.path.join(current_dir,'crawled_websites') # create a folder inside the current directory

#         if not os.isdir(folder_dir): # check if the folder already exists
#             os.makedirs(folder_dir) # if not, create the folder directory

#         filename = re.sub(r'\W+', '_', self.start_url) + '_crawling_results.json' # format the filename to modify unsupported characters
        
#         # save the results as a json file in the local directory
#         with open(os.path.join(folder_dir,filename), 'w', encoding='utf-8') as file:
#             json.dump(urls_content, file, ensure_ascii=False, indent=10) # ensure to keep the unicode characters and indent to make it more readable

#         return urls_content # return the disctionary storing all urls and their content                














#!/usr/bin/env python3
"""
Web API Security Scanner
Author: Security Analyst
Description: Discovers API endpoints, performs security tests, and generates a report
"""

import requests
import json
import re
import argparse
import time
import urllib.parse
from datetime import datetime
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

class APIScanner:
    def __init__(self, base_url, max_threads=5, delay=1):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'APISecurityScanner/1.0',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        })
        self.found_endpoints = set()
        self.vulnerabilities = []
        self.max_threads = max_threads
        self.delay = delay
        self.common_endpoints = [
            '/api/v1/users', '/api/users', '/api/v1/auth', '/api/auth',
            '/api/v1/login', '/api/login', '/api/v1/register', '/api/register',
            '/api/v1/admin', '/api/admin', '/api/v1/config', '/api/config',
            '/graphql', '/api/graphql', '/rest', '/api/rest', '/api/v1', '/api'
        ]
        self.common_parameters = ['id', 'user', 'user_id', 'admin', 'email', 
                                 'password', 'token', 'auth', 'key', 'query']

    def delay_request(self):
        """Respectful delay between requests"""
        time.sleep(self.delay)

    def discover_endpoints(self):
        """Discover API endpoints through various methods"""
        print(f"[*] Starting endpoint discovery on {self.base_url}")
        
        # Method 1: Check common API endpoints
        self.check_common_endpoints()
        
        # Method 2: Spider the main page for links
        self.spider_page(self.base_url)
        
        # Method 3: Check for API documentation
        self.check_api_documentation()
        
        # Method 4: Check JavaScript files for API endpoints
        self.check_js_files()
        
        print(f"[*] Found {len(self.found_endpoints)} potential API endpoints")
        return list(self.found_endpoints)

    def check_common_endpoints(self):
        """Check for commonly used API endpoints"""
        for endpoint in self.common_endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code < 400:
                    self.found_endpoints.add(url)
                    print(f"[+] Found endpoint: {url} ({response.status_code})")
                self.delay_request()
            except requests.RequestException:
                continue

    def spider_page(self, url):
        """Extract links from a page"""
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            for link in soup.find_all('a', href=True):
                href = link['href']
                full_url = self.normalize_url(href)
                if full_url and full_url.startswith(self.base_url):
                    # Check if it looks like an API endpoint
                    if self.is_api_endpoint(full_url):
                        self.found_endpoints.add(full_url)
                        print(f"[+] Found endpoint: {full_url}")
            
            self.delay_request()
        except requests.RequestException:
            pass

    def check_api_documentation(self):
        """Check for common API documentation endpoints"""
        doc_endpoints = [
            '/swagger', '/swagger-ui', '/swagger.json', '/api-docs', 
            '/redoc', '/openapi.json', '/api.html', '/doc', '/docs'
        ]
        
        for endpoint in doc_endpoints:
            url = f"{self.base_url}{endpoint}"
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code < 400:
                    self.found_endpoints.add(url)
                    print(f"[+] Found API documentation: {url}")
                self.delay_request()
            except requests.RequestException:
                continue

    def check_js_files(self):
        """Check JavaScript files for API endpoints"""
        try:
            response = self.session.get(self.base_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all JavaScript files
            for script in soup.find_all('script', src=True):
                js_url = self.normalize_url(script['src'])
                if js_url:
                    try:
                        js_response = self.session.get(js_url, timeout=10)
                        # Look for API endpoints in the JavaScript code
                        self.find_endpoints_in_js(js_response.text)
                    except requests.RequestException:
                        continue
                    self.delay_request()
        except requests.RequestException:
            pass

    def find_endpoints_in_js(self, js_code):
        """Find API endpoints in JavaScript code"""
        # Look for URL patterns
        patterns = [
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/\w+/\w+/\w+[^"\']*)["\']',
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.\w+\(["\']([^"\']+)["\']',
            r'\.ajax\([^{]*url:\s*["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_code)
            for match in matches:
                full_url = self.normalize_url(match)
                if full_url and self.is_api_endpoint(full_url):
                    self.found_endpoints.add(full_url)
                    print(f"[+] Found endpoint in JS: {full_url}")

    def normalize_url(self, url):
        """Normalize a URL to its full form"""
        if url.startswith('http'):
            return url
        elif url.startswith('//'):
            return f"https:{url}"
        elif url.startswith('/'):
            return f"{self.base_url}{url}"
        else:
            return f"{self.base_url}/{url}"

    def is_api_endpoint(self, url):
        """Check if a URL looks like an API endpoint"""
        api_patterns = [r'/api/', r'\.json', r'\.xml', r'/v\d+/', r'/graphql', r'/rest']
        for pattern in api_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        return False

    def test_endpoints(self, endpoints):
        """Test discovered endpoints for security vulnerabilities"""
        print(f"[*] Testing {len(endpoints)} endpoints for security issues")
        
        # Test each endpoint with multiple vulnerability checks
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_url = {
                executor.submit(self.test_endpoint, endpoint): endpoint 
                for endpoint in endpoints
            }
            
            for future in as_completed(future_to_url):
                endpoint = future_to_url[future]
                try:
                    future.result()
                except Exception as e:
                    print(f"[-] Error testing {endpoint}: {e}")
        
        print(f"[*] Completed security testing. Found {len(self.vulnerabilities)} potential issues")

    def test_endpoint(self, endpoint):
        """Test a single endpoint for multiple vulnerability types"""
        print(f"[*] Testing: {endpoint}")
        
        # Test for authentication bypass
        self.test_auth_bypass(endpoint)
        
        # Test for IDOR (Insecure Direct Object Reference)
        self.test_idor(endpoint)
        
        # Test for SQL injection
        self.test_sql_injection(endpoint)
        
        # Test for XSS
        self.test_xss(endpoint)
        
        # Test for information disclosure
        self.test_info_disclosure(endpoint)
        
        # Test for HTTP methods
        self.test_http_methods(endpoint)
        
        self.delay_request()

    def test_auth_bypass(self, url):
        """Test for authentication bypass vulnerabilities"""
        # Try accessing without authentication
        try:
            response = self.session.get(url, timeout=10)
            if response.status_code == 200:
                self.vulnerabilities.append({
                    'type': 'Authentication Bypass',
                    'endpoint': url,
                    'severity': 'High',
                    'description': 'Endpoint may be accessible without proper authentication',
                    'evidence': f'GET {url} returned 200 without authentication'
                })
        except requests.RequestException:
            pass

    def test_idor(self, url):
        """Test for IDOR vulnerabilities"""
        # Look for numeric IDs in the URL
        match = re.search(r'/(\d+)/?$', url)
        if match:
            test_id = str(int(match.group(1)) + 1)
            test_url = re.sub(r'/\d+/?$', f'/{test_id}', url)
            
            try:
                response = self.session.get(test_url, timeout=10)
                if response.status_code == 200:
                    self.vulnerabilities.append({
                        'type': 'IDOR (Insecure Direct Object Reference)',
                        'endpoint': test_url,
                        'severity': 'High',
                        'description': 'Endpoint may be vulnerable to IDOR by incrementing numeric IDs',
                        'evidence': f'GET {test_url} returned 200 with incremented ID'
                    })
            except requests.RequestException:
                pass

    def test_sql_injection(self, url):
        """Test for basic SQL injection vulnerabilities"""
        # Only test if URL has parameters
        if '?' in url:
            test_payloads = ["'", "' OR '1'='1", "1' ORDER BY 1--", "1 AND 1=1"]
            
            for payload in test_payloads:
                test_url = self.inject_payload(url, payload)
                try:
                    response = self.session.get(test_url, timeout=10)
                    if self.is_sql_error(response.text):
                        self.vulnerabilities.append({
                            'type': 'SQL Injection',
                            'endpoint': url,
                            'severity': 'Critical',
                            'description': f'Potential SQL injection with payload: {payload}',
                            'evidence': f'GET {test_url} returned possible SQL error'
                        })
                        break
                except requests.RequestException:
                    continue

    def test_xss(self, url):
        """Test for basic XSS vulnerabilities"""
        if '?' in url:
            test_payload = '<script>alert("XSS")</script>'
            test_url = self.inject_payload(url, test_payload)
            
            try:
                response = self.session.get(test_url, timeout=10)
                if test_payload in response.text:
                    self.vulnerabilities.append({
                        'type': 'Reflected XSS',
                        'endpoint': url,
                        'severity': 'Medium',
                        'description': 'Potential reflected XSS vulnerability',
                        'evidence': f'Payload reflected in response: {test_payload}'
                    })
            except requests.RequestException:
                pass

    def test_info_disclosure(self, url):
        """Test for information disclosure"""
        try:
            response = self.session.get(url, timeout=10)
            
            # Check for common information disclosure patterns
            info_patterns = [
                r'error.*(mysql|sqlserver|oracle|postgresql)',
                r'stack trace',
                r'file path',
                r'password.*(invalid|incorrect)',
                r'(username|user).*(invalid|incorrect)'
            ]
            
            for pattern in info_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self.vulnerabilities.append({
                        'type': 'Information Disclosure',
                        'endpoint': url,
                        'severity': 'Low',
                        'description': 'Endpoint may disclose sensitive information in errors',
                        'evidence': f'Found pattern "{pattern}" in response body'
                    })
                    break
        except requests.RequestException:
            pass

    def test_http_methods(self, url):
        """Test for potentially dangerous HTTP methods"""
        methods = ['PUT', 'DELETE', 'TRACE', 'OPTIONS']
        
        for method in methods:
            try:
                response = self.session.request(method, url, timeout=10)
                if response.status_code < 400:
                    self.vulnerabilities.append({
                        'type': 'HTTP Method Enabled',
                        'endpoint': url,
                        'severity': 'Medium' if method in ['PUT', 'DELETE'] else 'Low',
                        'description': f'Potentially dangerous HTTP method {method} is enabled',
                        'evidence': f'{method} {url} returned {response.status_code}'
                    })
            except requests.RequestException:
                continue

    def inject_payload(self, url, payload):
        """Inject a payload into URL parameters"""
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        
        # Inject payload into each parameter
        for param in query_params:
            query_params[param] = payload
        
        new_query = urllib.parse.urlencode(query_params, doseq=True)
        return urllib.parse.urlunparse((
            parsed_url.scheme,
            parsed_url.netloc,
            parsed_url.path,
            parsed_url.params,
            new_query,
            parsed_url.fragment
        ))

    def is_sql_error(self, text):
        """Check if response contains SQL error messages"""
        error_patterns = [
            r'syntax error',
            r'mysql.*error',
            r'ora-\d+',
            r'postgresql.*error',
            r'sqlserver.*error',
            r'unclosed quotation mark',
            r'unknown column'
        ]
        
        for pattern in error_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False

    def generate_report(self, filename=None):
        """Generate a security assessment report"""
        if filename is None:
            filename = f"api_security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        # Group vulnerabilities by severity
        critical = [v for v in self.vulnerabilities if v['severity'] == 'Critical']
        high = [v for v in self.vulnerabilities if v['severity'] == 'High']
        medium = [v for v in self.vulnerabilities if v['severity'] == 'Medium']
        low = [v for v in self.vulnerabilities if v['severity'] == 'Low']
        
        # Create HTML report
        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API Security Assessment Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                h1 {{ color: #333; }}
                .summary {{ background-color: #f5f5f5; padding: 20px; border-radius: 5px; }}
                .vuln {{ margin-bottom: 20px; border-left: 5px solid; padding-left: 15px; }}
                .critical {{ border-color: #d9534f; }}
                .high {{ border-color: #f0ad4e; }}
                .medium {{ border-color: #5bc0de; }}
                .low {{ border-color: #5cb85c; }}
                .severity-critical {{ color: #d9534f; font-weight: bold; }}
                .severity-high {{ color: #f0ad4e; font-weight: bold; }}
                .severity-medium {{ color: #5bc0de; font-weight: bold; }}
                .severity-low {{ color: #5cb85c; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h1>API Security Assessment Report</h1>
            <p><strong>Target:</strong> {self.base_url}</p>
            <p><strong>Scan Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <p><strong>Total Endpoints Found:</strong> {len(self.found_endpoints)}</p>
                <p><strong>Total Vulnerabilities:</strong> {len(self.vulnerabilities)}</p>
                <p><strong>Critical:</strong> {len(critical)} | 
                   <strong>High:</strong> {len(high)} | 
                   <strong>Medium:</strong> {len(medium)} | 
                   <strong>Low:</strong> {len(low)}</p>
            </div>
            
            <h2>Vulnerabilities</h2>
        """
        
        # Add vulnerabilities to report
        for vuln in self.vulnerabilities:
            severity_class = f"severity-{vuln['severity'].lower()}"
            html_content += f"""
            <div class="vuln {vuln['severity'].lower()}">
                <h3>{vuln['type']} <span class="{severity_class}">[{vuln['severity']}]</span></h3>
                <p><strong>Endpoint:</strong> {vuln['endpoint']}</p>
                <p><strong>Description:</strong> {vuln['description']}</p>
                <p><strong>Evidence:</strong> {vuln['evidence']}</p>
            </div>
            """
        
        # Add discovered endpoints section
        html_content += """
            <h2>Discovered Endpoints</h2>
            <ul>
        """
        
        for endpoint in self.found_endpoints:
            html_content += f"<li>{endpoint}</li>"
        
        html_content += """
            </ul>
        </body>
        </html>
        """
        
        # Write report to file
        with open(filename, 'w') as f:
            f.write(html_content)
        
        print(f"[+] Report generated: {filename}")
        return filename

def main():
    parser = argparse.ArgumentParser(description='Web API Security Scanner')
    parser.add_argument('url', help='Base URL to scan')
    parser.add_argument('-t', '--threads', type=int, default=5, 
                       help='Maximum number of concurrent threads (default: 5)')
    parser.add_argument('-d', '--delay', type=float, default=1.0,
                       help='Delay between requests in seconds (default: 1.0)')
    parser.add_argument('-o', '--output', help='Output report filename')
    
    args = parser.parse_args()
    
    # Create scanner instance
    scanner = APIScanner(args.url, args.threads, args.delay)
    
    # Discover endpoints
    endpoints = scanner.discover_endpoints()
    
    # Test endpoints for vulnerabilities
    scanner.test_endpoints(endpoints)
    
    # Generate report
    report_file = scanner.generate_report(args.output)
    
    print(f"\n[+] Scan completed. Check {report_file} for results.")

if __name__ == '__main__':
    main()