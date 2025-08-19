import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import time

# Step 1: Input Acceptance and Validation
website = input("Enter the website URL (e.g., http://example.com): ")
print("WARNING: Ensure you have explicit permission to scan this website.")
try:
    response = requests.get(website, timeout=5)
    if response.status_code == 200:
        print("Website is reachable.")
    else:
        print("Website is not reachable. Status code:", response.status_code)
        exit()
except requests.exceptions.RequestException as e:
    print("An error occurred:", e)
    exit()

# Step 4: Generating XSS Payloads
payloads = [
    "<script>alert('XSS')</script>",
    "<img src=1 onerror=alert('XSS')>",
    "<ScRipt>alert('XSS')</ScRipt>",
    "'><img src=1 onerror=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>"
]

visited = set()
max_depth = 2
vulnerabilities = []  # To store detected vulnerabilities

# Step 5: Injecting Payloads (and basic analysis)
def test_injection_point(url, injection_point, payload):
    results = []
    
    if injection_point['type'] == 'url_param':
        param_name = injection_point['param']
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        test_url = f"{base_url}?{param_name}={payload}"
        
        try:
            response = requests.get(test_url, timeout=5)
            result = {
                'request': test_url,
                'response': response.text,
                'payload': payload,
                'type': 'url_param',
                'param': param_name
            }
            # Basic analysis (Step 6): Check if payload is reflected unsanitized
            if payload in response.text:
                vulnerabilities.append({
                    'url': url,
                    'type': 'url_param',
                    'param': param_name,
                    'payload': payload,
                    'request': test_url
                })
                print(f"[VULNERABILITY] Reflected payload in URL param: {param_name}, Payload: {payload}")
            results.append(result)
        except requests.RequestException as e:
            results.append({
                'request': test_url,
                'response': str(e),
                'payload': payload,
                'type': 'url_param',
                'error': True
            })
    
    elif injection_point['type'] == 'form':
        form_url = injection_point['action']
        method = injection_point['method'].lower()
        fields = injection_point['fields']
        data = {field: payload for field in fields}
        
        try:
            if method == 'post':
                response = requests.post(form_url, data=data, timeout=5)
            else:
                response = requests.get(form_url, params=data, timeout=5)
            
            result = {
                'request': {'url': form_url, 'method': method, 'data': data},
                'response': response.text,
                'payload': payload,
                'type': 'form'
            }
            # Basic analysis (Step 6): Check if payload is reflected unsanitized
            if payload in response.text:
                vulnerabilities.append({
                    'url': url,
                    'type': 'form',
                    'method': method,
                    'fields': fields,
                    'payload': payload,
                    'request': result['request']
                })
                print(f"[VULNERABILITY] Reflected payload in form, Method: {method}, Payload: {payload}")
            results.append(result)
            
            # Test alternative method (GET/POST) if applicable
            alt_method = 'get' if method == 'post' else 'post'
            try:
                if alt_method == 'post':
                    response = requests.post(form_url, data=data, timeout=5)
                else:
                    response = requests.get(form_url, params=data, timeout=5)
                result = {
                    'request': {'url': form_url, 'method': alt_method, 'data': data},
                    'response': response.text,
                    'payload': payload,
                    'type': 'form'
                }
                if payload in response.text:
                    vulnerabilities.append({
                        'url': url,
                        'type': 'form',
                        'method': alt_method,
                        'fields': fields,
                        'payload': payload,
                        'request': result['request']
                    })
                    print(f"[VULNERABILITY] Reflected payload in form, Method: {alt_method}, Payload: {payload}")
                results.append(result)
            except requests.RequestException:
                pass  # Skip alternative method errors for simplicity
        
        except requests.RequestException as e:
            results.append({
                'request': {'url': form_url, 'method': method, 'data': data},
                'response': str(e),
                'payload': payload,
                'type': 'form',
                'error': True
            })
    
    return results

# Step 7: Reporting Results
def generate_report():
    report = "XSS Vulnerability Scan Report\n"
    report += f"Generated on: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    report += f"Target: {website}\n\n"
    
    if not vulnerabilities:
        report += "No vulnerabilities found.\n"
    else:
        for vuln in vulnerabilities:
            report += f"Vulnerability Found:\n"
            report += f"URL: {vuln['url']}\n"
            report += f"Type: {vuln['type']}\n"
            if vuln['type'] == 'url_param':
                report += f"Parameter: {vuln['param']}\n"
            else:
                report += f"Method: {vuln['method']}, Fields: {vuln['fields']}\n"
            report += f"Payload: {vuln['payload']}\n"
            report += f"Request: {vuln['request']}\n"
            report += "-" * 50 + "\n"
    
    print(report)
    with open('xss_scan_report.txt', 'w') as f:
        f.write(report)

# Step 2 & 3: Crawling and Identifying Injection Points
def crawler(url, depth=0):
    if depth > max_depth or url in visited:
        return
    visited.add(url)  # Fixed bug: was adding 1 instead of url
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        # Step 3: Identify forms
        forms = soup.find_all("form")
        for f in forms:
            action = urljoin(url, f.get("action", url))
            method = f.get("method", "get").upper()
            inputs = [i.get("name") for i in f.find_all(["input", "textarea", "select", "button"]) if i.get("name")]
            if inputs:  # Only process forms with inputs
                print(f"[FORM] URL: {url}, Action: {action}, Method: {method}, Inputs: {inputs}")
                # Step 5: Test form injection
                injection_point = {'type': 'form', 'action': action, 'method': method, 'fields': inputs}
                for p in payloads:
                    print(f"[PAYLOAD] Form, Payload: {p}")
                    test_injection_point(url, injection_point, p)

        # Step 3: Identify URL parameters
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            print(f"[PARAMS] URL: {url}, Parameters: {list(params.keys())}")
            for param in params:
                injection_point = {'type': 'url_param', 'param': param}
                for p in payloads:
                    print(f"[PAYLOAD] URLParam: {param}, Payload: {p}")
                    test_injection_point(url, injection_point, p)

        # Step 2: Continue crawling
        for link in soup.find_all("a", href=True):
            next_url = urljoin(url, link['href'])
            if urlparse(next_url).netloc == urlparse(website).netloc:
                crawler(next_url, depth + 1)
    except requests.RequestException:
        pass

# Run the scanner
crawler(website)
generate_report()