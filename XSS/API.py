#!/usr/bin/env python3
import requests
import argparse
import json
import time
import re
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed
import jwt
from openapi_spec_validator import validate_spec_url, OpenApi30SpecValidator

DEFAULT_TIMEOUT = 10
UA = {"User-Agent": "API-Endpoint-Tester/1.0"}

# Common API endpoints to test
COMMON_ENDPOINTS = [
    "/users", "/users/1", "/posts", "/posts/1", "/comments", "/products",
    "/api/v1/users", "/api/v2/users", "/api/v1/posts", "/api/v3/docs",
    "/swagger.json", "/openapi.json", "/v3/api-docs", "/api-docs", "/swagger-ui.html"
]

def parse_arguments():
    parser = argparse.ArgumentParser(description="API Endpoint Tester for OWASP API Security Top 10")
    parser.add_argument("url", help="Base URL of the API (e.g., https://api.example.com)")
    parser.add_argument("--token", help="Bearer token for authenticated requests")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads for scanning (default: 10)")
    return parser.parse_args()

def discover_endpoints(base_url, headers):
    """Discover endpoints by testing common paths and parsing OpenAPI specs"""
    endpoints = set(COMMON_ENDPOINTS)
    # Try to fetch and parse OpenAPI/Swagger specs
    spec_paths = ["/swagger.json", "/openapi.json", "/v3/api-docs", "/api-docs"]
    for spec_path in spec_paths:
        try:
            spec_url = f"{base_url}{spec_path}"
            response = requests.get(spec_url, headers=headers, timeout=DEFAULT_TIMEOUT)
            if response.status_code == 200:
                spec = response.json()
                validator = OpenApi30SpecValidator(spec)
                validator.validate()
                # Extract paths from OpenAPI spec
                for path in spec.get("paths", {}):
                    endpoints.add(path)
        except Exception:
            continue
    return list(endpoints)

def safe_request(url, headers, method="GET", params=None, json_body=None):
    """Make a safe HTTP request with error handling"""
    try:
        if method == "GET":
            return requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
        elif method == "POST":
            return requests.post(url, headers=headers, json=json_body, timeout=DEFAULT_TIMEOUT)
        elif method == "PUT":
            return requests.put(url, headers=headers, json=json_body, timeout=DEFAULT_TIMEOUT)
        elif method == "DELETE":
            return requests.delete(url, headers=headers, timeout=DEFAULT_TIMEOUT)
    except requests.RequestException:
        return None

def detect_numeric_id(url):
    """Detect numeric ID in URL path or query parameters"""
    path_parts = [p for p in urlparse(url).path.split("/") if p]
    if path_parts and re.fullmatch(r"\d+", path_parts[-1]):
        return int(path_parts[-1])
    q = parse_qs(urlparse(url).query)
    for key in ("id", "userId", "accountId", "postId"):
        if key in q and re.fullmatch(r"\d+", q[key][0]):
            return int(q[key][0])
    return None

def replace_numeric_id(url, new_id):
    """Replace numeric ID in URL path or query parameters"""
    u = urlparse(url)
    parts = [p for p in u.path.split("/") if p]
    if parts and re.fullmatch(r"\d+", parts[-1]):
        parts[-1] = str(new_id)
        return urlunparse(u._replace(path="/" + "/".join(parts)))
    q = parse_qs(u.query)
    for key in ("id", "userId", "accountId", "postId"):
        if key in q:
            q[key] = [str(new_id)]
            return urlunparse(u._replace(query=urlencode({k: v[0] for k, v in q.items()})))
    return url

def test_bola(url, headers):
    """Test for API1: Broken Object Level Authorization"""
    issues = []
    base_id = detect_numeric_id(url)
    if not base_id:
        return issues
    candidates = [i for i in {base_id-1, base_id+1, base_id+10, 1} if i > 0 and i != base_id]
    baseline = safe_request(url, headers)
    if not baseline or baseline.status_code != 200:
        return issues
    base_sig = (baseline.status_code, len(baseline.content or b""))
    for nid in candidates:
        test_url = replace_numeric_id(url, nid)
        r = safe_request(test_url, headers)
        if r and r.status_code == 200 and abs(len(r.content or b"") - base_sig[1]) < max(64, 0.1*base_sig[1]):
            issues.append(("API1: Broken Object Level Authorization", f"Accessible object ID {nid} at {test_url}"))
    return issues

def test_broken_auth(url, headers, token):
    """Test for API2: Broken Authentication"""
    issues = []
    no_auth_headers = dict(UA)
    r_no_auth = safe_request(url, no_auth_headers)
    if r_no_auth and r_no_auth.status_code == 200:
        issues.append(("API2: Broken Authentication", "Accessed endpoint without auth"))
    if token:
        invalid_headers = dict(UA, Authorization=f"Bearer invalid_{token}")
        r_invalid = safe_request(url, invalid_headers)
        if r_invalid and r_invalid.status_code == 200:
            issues.append(("API2: Broken Authentication", "Accessed endpoint with invalid token"))
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            if decoded.get("alg") == "none":
                issues.append(("API2: Broken Authentication", "JWT with 'none' algorithm"))
            if "exp" not in decoded:
                issues.append(("API2: Broken Authentication", "JWT without expiration"))
        except:
            pass
    return issues

def test_object_property_auth(url, headers):
    """Test for API3: Broken Object Property Level Authorization"""
    issues = []
    payload = {"_test_field": "probe", "admin": True}
    r = safe_request(url, headers, method="POST", json_body=payload)
    if r and r.status_code in (200, 201) and any(k in (r.text or "") for k in payload.keys()):
        issues.append(("API3: Broken Object Property Level Authorization", "Server accepts unexpected fields"))
    r_get = safe_request(url, headers)
    if r_get and r_get.status_code == 200:
        sensitive = ["password", "credit_card", "ssn"]
        if any(kw in r_get.text.lower() for kw in sensitive):
            issues.append(("API3: Broken Object Property Level Authorization", "Sensitive data exposed"))
    return issues

def test_rate_limit(url, headers):
    """Test for API4: Unrestricted Resource Consumption"""
    issues = []
    results = []
    def call():
        r = safe_request(url, headers)
        return (r.status_code if r else "err", r.headers.get("X-RateLimit-Remaining") if r else None)
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(call) for _ in range(30)]
        for f in as_completed(futs):
            results.append(f.result())
    if not any(s == 429 for s, _ in results) and not any(r for _, r in results):
        issues.append(("API4: Unrestricted Resource Consumption", "No rate limiting detected"))
    return issues

def test_ssrf(url, headers):
    """Test for API7: Server-Side Request Forgery"""
    issues = []
    params = {"url": "http://169.254.169.254/latest/meta-data/"}
    r = safe_request(url, headers, params=params)
    if r and r.status_code == 200 and len(r.content) > 0:
        issues.append(("API7: Server-Side Request Forgery", "Potential SSRF to metadata service"))
    return issues

def test_security_misconfig(url, headers):
    """Test for API8: Security Misconfiguration"""
    issues = []
    r = safe_request(url, headers)
    if not r:
        return issues
    headers_check = {
        "X-Content-Type-Options": "nosniff",
        "Strict-Transport-Security": lambda v: "max-age" in v
    }
    for h, expected in headers_check.items():
        val = r.headers.get(h)
        if not val or (callable(expected) and not expected(val)):
            issues.append(("API8: Security Misconfiguration", f"Missing/weak header: {h}"))
    if not url.lower().startswith("https://"):
        issues.append(("API8: Security Misconfiguration", "API uses HTTP instead of HTTPS"))
    return issues

def test_endpoint(url, headers, token):
    """Test a single endpoint for vulnerabilities"""
    issues = []
    issues.extend(test_bola(url, headers))
    issues.extend(test_broken_auth(url, headers, token))
    issues.extend(test_object_property_auth(url, headers))
    issues.extend(test_rate_limit(url, headers))
    issues.extend(test_ssrf(url, headers))
    issues.extend(test_security_misconfig(url, headers))
    return issues

def main():
    args = parse_arguments()
    base_url = args.url.rstrip("/")
    headers = dict(UA)
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    print(f"\n=== API Endpoint Tester ===\nTarget: {base_url}\n")

    # Discover endpoints
    endpoints = discover_endpoints(base_url, headers)
    report = {
        "target": base_url,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "endpoints_tested": [],
        "findings": [],
        "notes": ["Tests for OWASP API Security Top 10 2023"]
    }

    # Test endpoints concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(test_endpoint, f"{base_url}{ep}", headers, args.token): ep for ep in endpoints}
        for future in as_completed(futures):
            ep = futures[future]
            try:
                issues = future.result()
                report["endpoints_tested"].append({"endpoint": ep, "issues": issues})
                for issue in issues:
                    report["findings"].append({"endpoint": ep, "category": issue[0], "message": issue[1]})
            except Exception as e:
                report["findings"].append({"endpoint": ep, "category": "Error", "message": str(e)})

    # Print report
    print("=== Test Results ===")
    print(f"Endpoints Tested: {len(endpoints)}")
    if report["findings"]:
        print("\nFindings:")
        for i, f in enumerate(report["findings"], 1):
            print(f" {i:02d}. [{f['category']}] {f['endpoint']}: {f['message']}")
    else:
        print("\nNo issues detected.")
    print("\nNotes:")
    for note in report["notes"]:
        print(f" - {note}")

    # Save report
    with open("api_test_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print("\nSaved: api_test_report.json")

if __name__ == "__main__":
    main()