import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

class XSSScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.visited = set()
        self.vulns = []
        self.tested_forms = set()  
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')></iframe>"
        ]

    def is_reflected(self, response, payload):
        return payload in response
    def submit_payload(self, url, method, data, input_name, payload):
        try:
            if method == "post":
                resp = self.session.post(url, data=data, timeout=5)
            else:
                resp = self.session.get(url, params=data, timeout=5)
            if self.is_reflected(resp.text, payload):
                vuln = {
                    "url": url,
                    "input": input_name,
                    "payload": payload,
                    "method": method.upper(),
                    "type": "Reflected",
                    "severity": "High"
                }
                if vuln not in self.vulns:
                    self.vulns.append(vuln)
        except requests.RequestException:
            pass  
    def test_inputs(self, url):
        try:
            response = self.session.get(url, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            tasks = []
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action", url))
                method = form.get("method", "get").lower()
                inputs = {i.get("name"): "test" for i in form.find_all(["input", "textarea"]) if i.get("name")}
                form_key = (action, tuple(sorted(inputs.keys())))  # Unique form identifier
                if not inputs or form_key in self.tested_forms:
                    continue
                self.tested_forms.add(form_key)
                for name in inputs:
                    for payload in self.payloads:
                        data = inputs.copy()
                        data[name] = payload
                        tasks.append((action, method, data, name, payload))
            with ThreadPoolExecutor(max_workers=2) as executor:
                executor.map(lambda t: self.submit_payload(*t), tasks)
            params = parse_qs(urlparse(url).query)
            for param in params:
                for payload in self.payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    self.submit_payload(url, "get", test_params, param, payload)
        except requests.RequestException:
            pass  
    def crawl(self, url, depth=0, max_depth=2):
        """Crawl website and test each page for XSS."""
        if depth > max_depth or url in self.visited:
            return
        self.visited.add(url)
        self.test_inputs(url)
        try:
            soup = BeautifulSoup(self.session.get(url, timeout=5).text, "html.parser")
            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link['href'])
                if urlparse(next_url).netloc == urlparse(self.base_url).netloc:
                    self.crawl(next_url, depth + 1, max_depth)
        except requests.RequestException:
            pass 
    def report(self):
        """Print and save a formatted vulnerability report."""
        report = ["=== XSS Vulnerability Report ===", f"Target: {self.base_url}", f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}"]
        if not self.vulns:
            report.append("No XSS vulnerabilities found.")
        else:
            for vuln in self.vulns:
                report.append(f"""
URL: {vuln['url']}
Input: {vuln['input']}
Payload: {vuln['payload']}
Method: {vuln['method']}
Type: {vuln['type']}
Severity: {vuln['severity']}
-------------------""")
        
        report_text = "\n".join(report)
        print(report_text)
        with open("xss_report.txt", "w") as f:
            f.write(report_text)

if __name__ == "__main__":
    import time
    print("WARNING: Only scan websites you have explicit permission to test.")
    url = input("Enter website URL (e.g., http://example.com): ")
    try:
        if requests.get(url, timeout=5).status_code != 200:
            print("Website is unreachable.")
            exit()
    except requests.RequestException:
        print("Error accessing website.")
        exit()
    scanner = XSSScanner(url)
    scanner.crawl(url)
    scanner.report()