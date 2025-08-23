#!/usr/bin/env python3
import sys, json, time, re, random, hashlib, hmac, base64
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs, quote
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import jwt as pyjwt
from datetime import datetime, timedelta

DEFAULT_TIMEOUT = 8
UA = {"User-Agent": "api-guardian/2.0"}
COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[34m",
    "INFO": "\033[36m",
    "RESET": "\033[0m"
}

def jlen(resp):
    try:
        return len(resp.json())
    except Exception:
        return None

def status_body_size(resp):
    try:
        return resp.status_code, len(resp.content or b"")
    except Exception:
        return None, None

def safe_get(url, headers=None, params=None, method="GET", json_body=None, data=None, allow_redirects=True):
    try:
        if method == "GET":
            return requests.get(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
        elif method == "POST":
            return requests.post(url, headers=headers, json=json_body, data=data, params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
        elif method == "PUT":
            return requests.put(url, headers=headers, json=json_body, data=data, params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
        elif method == "PATCH":
            return requests.patch(url, headers=headers, json=json_body, data=data, params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
        elif method == "DELETE":
            return requests.delete(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
        elif method == "HEAD":
            return requests.head(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
        elif method == "OPTIONS":
            return requests.options(url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT, allow_redirects=allow_redirects)
    except requests.RequestException as e:
        return None

def url_with_params(base, extra):
    u = urlparse(base)
    q = parse_qs(u.query)
    q.update(extra)
    return urlunparse(u._replace(query=urlencode({k:v for k,v in ((k, list(v)[0] if isinstance(v, list) else v) for k,v in q.items())})))

def detect_numeric_id(url):
    """Find last numeric path segment if any (useful for IDOR checks)"""
    path_parts = [p for p in urlparse(url).path.split("/") if p]
    if not path_parts: return None
    if re.fullmatch(r"\d+", path_parts[-1]): 
        return int(path_parts[-1])
    # Try id query parameter
    q = parse_qs(urlparse(url).query)
    for key in ("id","userId","accountId","postId","orderId","productId","customerId"):
        if key in q and re.fullmatch(r"\d+", q[key][0]): 
            return int(q[key][0])
    return None

def replace_numeric_id(url, new_id):
    u = urlparse(url)
    parts = [p for p in u.path.split("/") if p]
    if parts and re.fullmatch(r"\d+", parts[-1]):
        parts[-1] = str(new_id)
        return urlunparse(u._replace(path="/" + "/".join(parts)))
    q = parse_qs(u.query)
    for key in ("id","userId","accountId","postId","orderId","productId","customerId"):
        if key in q:
            q[key] = [str(new_id)]
            return urlunparse(u._replace(query=urlencode({k:v[0] for k,v in q.items()})))
    return url  # fallback

def generate_jwt_payloads(secret_key=None):
    """Generate various JWT test payloads"""
    payloads = []
    
    # None algorithm attack
    payload_none = {"alg": "none", "typ": "JWT"}
    encoded_none = base64.urlsafe_b64encode(json.dumps(payload_none).encode()).decode().rstrip("=")
    payloads.append(("None algorithm", f"{encoded_none}.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."))
    
    # HS256 with weak secret
    weak_secrets = ["secret", "password", "123456", "admin", "token", "key"]
    for secret in weak_secrets:
        try:
            token = pyjwt.encode({"user": "admin", "exp": datetime.utcnow() + timedelta(hours=1)}, secret, algorithm="HS256")
            payloads.append(("Weak secret", token))
        except:
            pass
    
    return payloads

def check_jwt_vulnerabilities(url, headers):
    """Check for JWT vulnerabilities"""
    issues = []
    jwt_tokens = []
    
    # Check if current response contains JWT
    response = safe_get(url, headers=headers, method="GET")
    if response:
        # Look for JWTs in response
        jwt_pattern = r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*"
        found_jwts = re.findall(jwt_pattern, response.text)
        jwt_tokens.extend(found_jwts)
    
    # Test JWT endpoints
    jwt_endpoints = ["/auth/login", "/api/login", "/token", "/oauth/token", "/api/token"]
    for endpoint in jwt_endpoints:
        test_url = url.rstrip("/") + endpoint
        test_response = safe_get(test_url, headers=headers, method="POST", json_body={"username": "admin", "password": "admin"})
        if test_response and test_response.status_code == 200:
            found_jwts = re.findall(jwt_pattern, test_response.text)
            jwt_tokens.extend(found_jwts)
    
    # Test each found JWT
    for token in set(jwt_tokens):
        try:
            # Try decoding without verification
            decoded = pyjwt.decode(token, options={"verify_signature": False})
            issues.append(("JWT - No Verification", f"JWT decoded without signature verification: {decoded}"))
            
            # Test for none algorithm
            header = pyjwt.get_unverified_header(token)
            if header.get("alg") == "none":
                issues.append(("JWT - None Algorithm", "JWT uses 'none' algorithm vulnerability"))
                
        except Exception as e:
            pass
    
    return issues, jwt_tokens

def check_ssrf(url, headers):
    """Check for Server-Side Request Forgery vulnerabilities"""
    issues = []
    test_payloads = [
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:22/",
        "http://127.0.0.1:22/",
        "http://[::1]:22/",
        "http://internal.api.company.com/",
        "file:///etc/passwd"
    ]
    
    # Test in parameters
    u = urlparse(url)
    query_params = parse_qs(u.query)
    
    for param_name in query_params:
        for payload in test_payloads:
            test_params = {param_name: payload}
            test_url = url_with_params(url, test_params)
            response = safe_get(test_url, headers=headers, method="GET")
            
            if response and response.status_code == 200:
                # Check for signs of SSRF response
                if any(indicator in response.text for indicator in ["instance-id", "AMI ID", "root:", "daemon:"]):
                    issues.append(("SSRF", f"Potential SSRF vulnerability in parameter '{param_name}' with payload: {payload}"))
    
    return issues, []

def check_xss_api(url, headers):
    """Check for XSS in API responses that might be rendered in web interfaces"""
    issues = []
    xss_payloads = [
        "<script>alert('XSS')</script>",
        "\"><script>alert('XSS')</script>",
        "javascript:alert('XSS')",
        "onerror=alert('XSS')"
    ]
    
    # Test in parameters
    u = urlparse(url)
    query_params = parse_qs(u.query)
    
    for param_name in query_params:
        for payload in xss_payloads:
            test_params = {param_name: payload}
            test_url = url_with_params(url, test_params)
            response = safe_get(test_url, headers=headers, method="GET")
            
            if response and response.status_code == 200:
                # Check if payload is reflected in response
                if payload in response.text:
                    issues.append(("XSS - Reflection", f"XSS payload reflected in parameter '{param_name}': {payload}"))
    
    return issues, []

def check_sql_injection(url, headers):
    """Check for SQL injection vulnerabilities"""
    issues = []
    sql_payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "1; DROP TABLE users--",
        "admin'--",
        "1' OR '1'='1",
        "1' UNION SELECT 1,2,3--",
        "1' AND 1=CONVERT(int, (SELECT @@version))--"
    ]
    
    # Test in parameters
    u = urlparse(url)
    query_params = parse_qs(u.query)
    
    for param_name in query_params:
        for payload in sql_payloads:
            test_params = {param_name: payload}
            test_url = url_with_params(url, test_params)
            response = safe_get(test_url, headers=headers, method="GET")
            
            if response and response.status_code == 200:
                # Check for SQL error messages
                error_indicators = [
                    "sql", "syntax", "mysql", "postgresql", "database",
                    "query failed", "unclosed quotation mark", "ORA-",
                    "SQLite", "ODBC", "JDBC", "driver", "connection"
                ]
                
                if any(indicator in response.text.lower() for indicator in error_indicators):
                    issues.append(("SQL Injection", f"Potential SQLi in parameter '{param_name}' with payload: {payload}"))
    
    return issues, []

def check_no_sql_injection(url, headers):
    """Check for NoSQL injection vulnerabilities"""
    issues = []
    nosql_payloads = [
        {"$ne": 1},
        {"$gt": 0},
        {"$where": "1 == 1"},
        {"$regex": ".*"}
    ]
    
    # Test JSON body for NoSQL injection
    for payload in nosql_payloads:
        response = safe_get(url, headers=headers, method="POST", json_body={"username": payload, "password": "test"})
        
        if response and response.status_code == 200:
            issues.append(("NoSQL Injection", f"Potential NoSQL injection with payload: {payload}"))
    
    return issues, []

def check_command_injection(url, headers):
    """Check for command injection vulnerabilities"""
    issues = []
    cmd_payloads = [
        "; ls -la",
        "| whoami",
        "`id`",
        "$(cat /etc/passwd)",
        "|| ping -c 1 localhost",
        "&& dir"
    ]
    
    # Test in parameters
    u = urlparse(url)
    query_params = parse_qs(u.query)
    
    for param_name in query_params:
        for payload in cmd_payloads:
            test_params = {param_name: payload}
            test_url = url_with_params(url, test_params)
            response = safe_get(test_url, headers=headers, method="GET")
            
            if response and response.status_code == 200:
                # Check for command output indicators
                output_indicators = [
                    "root", "bin", "etc", "usr", "var", "total",
                    "drwx", "-rw-r--r--", "uid=", "gid="
                ]
                
                if any(indicator in response.text for indicator in output_indicators):
                    issues.append(("Command Injection", f"Potential command injection in parameter '{param_name}' with payload: {payload}"))
    
    return issues, []

def check_xxe(url, headers):
    """Check for XXE vulnerabilities"""
    issues = []
    xxe_payloads = [
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "http://localhost:22/">]><root>&xxe;</root>'
    ]
    
    # Test if endpoint accepts XML
    xml_headers = {"Content-Type": "application/xml"}
    xml_headers.update(headers)
    
    for payload in xxe_payloads:
        response = safe_get(url, headers=xml_headers, method="POST", data=payload)
        
        if response and response.status_code == 200:
            # Check for file content in response
            if "root:" in response.text or "daemon:" in response.text:
                issues.append(("XXE", "Potential XXE vulnerability detected"))
    
    return issues, []

def check_broken_access_control(url, headers):
    """Check for broken access control vulnerabilities"""
    issues = []
    
    # Test admin endpoints without admin privileges
    admin_endpoints = [
        "/admin", "/api/admin", "/administrator", "/api/administrator",
        "/config", "/api/config", "/settings", "/api/settings"
    ]
    
    for endpoint in admin_endpoints:
        test_url = url.rstrip("/") + endpoint
        response = safe_get(test_url, headers=headers, method="GET")
        
        if response and response.status_code == 200:
            issues.append(("Broken Access Control", f"Access to admin endpoint {endpoint} without proper authorization"))
    
    return issues, []

def check_insecure_deserialization(url, headers):
    """Check for insecure deserialization vulnerabilities"""
    issues = []
    
    # Test Java serialized objects
    java_serialized = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAAAIAAAAC"
    java_headers = {"Content-Type": "application/java-serialized-object"}
    java_headers.update(headers)
    
    response = safe_get(url, headers=java_headers, method="POST", data=base64.b64decode(java_serialized))
    
    if response and response.status_code == 200:
        issues.append(("Insecure Deserialization", "Potential Java deserialization vulnerability"))
    
    return issues, []

def check_security_misconfiguration(url, headers):
    """Check for security misconfigurations"""
    issues = []
    
    # Check common exposed files
    exposed_files = [
        "/.env", "/.git/config", "/.DS_Store", "/web.config",
        "/phpinfo.php", "/info.php", "/server-status", "/.well-known/security.txt"
    ]
    
    for file in exposed_files:
        test_url = url.rstrip("/") + file
        response = safe_get(test_url, headers=headers, method="GET")
        
        if response and response.status_code == 200:
            issues.append(("Security Misconfiguration", f"Exposed sensitive file: {file}"))
    
    # Check HTTP methods
    methods = ["PUT", "DELETE", "TRACE", "CONNECT"]
    for method in methods:
        response = safe_get(url, headers=headers, method=method)
        if response and response.status_code not in [405, 501]:
            issues.append(("Security Misconfiguration", f"Dangerous HTTP method {method} enabled"))
    
    return issues, []

def check_basic(url, headers):
    issues = []
    # HTTPS
    if not url.lower().startswith("https://"):
        issues.append(("Transport", "API over plain HTTP (no TLS). Use HTTPS only.", "HIGH"))

    # Reachability
    r = safe_get(url, headers=headers, method="GET")
    if not r: 
        issues.append(("Availability", "Endpoint not reachable or timed out.", "HIGH"))
        return issues, None
    if r.status_code >= 500:
        issues.append(("Stability", f"Server error on GET: {r.status_code} (error leakage risk).", "MEDIUM"))
    if r.status_code in (401, 403):
        issues.append(("Auth", f"Endpoint requires auth (GET returned {r.status_code}).", "INFO"))

    # Security headers (for APIs often minimal, but caching matters)
    cache = r.headers.get("Cache-Control","").lower()
    if any(k in cache for k in ("public","no-transform")) or ("private" not in cache and "no-store" not in cache):
        issues.append(("Sensitive Data Caching", "No strict cache controls (add `no-store, private` for sensitive responses).", "MEDIUM"))

    # CORS
    opt = safe_get(url, headers=headers, method="OPTIONS")
    if opt and opt.headers.get("Access-Control-Allow-Origin") in ("*", "null"):
        issues.append(("CORS", "Wildcard ACAO detected. Consider restricting origins.", "MEDIUM"))

    return issues, r

def check_methods(url, headers):
    issues = []
    allowed_hdr = None
    opt = safe_get(url, headers=headers, method="OPTIONS")
    if opt:
        allowed_hdr = opt.headers.get("Allow") or opt.headers.get("Access-Control-Allow-Methods")
    tested = {}
    for m in ["HEAD","POST","PUT","PATCH","DELETE"]:
        r = safe_get(url, headers=headers, method=m, json_body={"_probe": True})
        if r:
            tested[m] = r.status_code
            if m != "HEAD" and r.status_code in (200,201,202,204):
                issues.append(("Excessive Methods", f"{m} allowed (status {r.status_code}) on this resource. Verify it's intended.", "LOW"))
        else:
            tested[m] = "timeout"
    if allowed_hdr:
        issues.append(("Discovery", f"Advertised allowed methods: {allowed_hdr}", "INFO"))
    return issues, tested

def check_rate_limit(url, headers):
    issues = []
    results = []
    def call():
        r = safe_get(url, headers=headers, method="GET")
        if not r: return ("err", None, None)
        return (r.status_code, r.headers.get("X-RateLimit-Remaining"), r.headers.get("Retry-After"))
    with ThreadPoolExecutor(max_workers=12) as ex:
        futs = [ex.submit(call) for _ in range(30)]
        for f in as_completed(futs):
            results.append(f.result())
    # Look for 429 presence or rate headers
    saw_429 = any(s == 429 for s,_,_ in results)
    has_headers = any(rr for _,rr,_ in results if rr is not None)
    if not saw_429 and not has_headers:
        issues.append(("Rate Limiting", "No evidence of throttling headers or 429 under burst (30 req). Consider rate limits.", "MEDIUM"))
    return issues, results

def check_idor(url, headers):
    """Heuristic BOLA/IDOR probe by neighboring IDs; read-only GETs only."""
    base_id = detect_numeric_id(url)
    if base_id is None:
        return [], None
    candidates = [i for i in {base_id-1, base_id+1, base_id-2, base_id+2} if i > 0]
    baseline = safe_get(url, headers=headers, method="GET")
    if not baseline: 
        return [], None
    base_sig = (baseline.status_code, len(baseline.content or b""))
    hits = []
    for nid in candidates:
        test_url = replace_numeric_id(url, nid)
        r = safe_get(test_url, headers=headers, method="GET")
        if not r: 
            continue
        sig = (r.status_code, len(r.content or b""))
        # If neighbor returns 200 and similar size, flag
        if r.status_code == 200 and abs(sig[1] - base_sig[1]) < max(64, 0.1*base_sig[1]):
            hits.append((test_url, r.status_code, sig[1]))
    issues = []
    if hits:
        issues.append(("BOLA/IDOR", f"Neighbor object(s) readable without change in auth: {len(hits)} similar responses.", "HIGH"))
    return issues, hits

def check_mass_assignment(url, headers):
    """Try sending an unexpected field on POST/PATCH; see if accepted back."""
    # Guess writable by presence of GET 200; we'll still try POST/PATCH safely.
    payload = {"_unexpected_field_"+str(random.randint(100,999)): "probe"}
    r = safe_get(url, headers=headers, method="POST", json_body=payload)
    issues = []
    if r and r.status_code in (200,201) and any(k in (r.text or "") for k in payload.keys()):
        issues.append(("Mass Assignment", "Server appears to accept unexpected fields (echoed in response). Validate allow-lists.", "MEDIUM"))
    return issues, r.status_code if r else None

def check_error_leak(url, headers):
    bad = "{ not: valid json"  # malformed
    r = None
    try:
        r = requests.post(url, headers={**headers, "Content-Type":"application/json"}, data=bad, timeout=DEFAULT_TIMEOUT)
    except Exception:
        pass
    issues = []
    if r and r.status_code >= 500:
        if re.search(r"(Traceback|Exception|at\s+.+\(.+\))", r.text, re.I):
            issues.append(("Error Handling", "Stack trace or framework error leaked. Return sanitized errors.", "MEDIUM"))
        else:
            issues.append(("Error Handling", "Server 5xx on malformed JSON. Harden input validation.", "LOW"))
    return issues, r.status_code if r else None

def check_pagination_abuse(url, headers):
    u = urlparse(url)
    q = parse_qs(u.query)
    # Try common params
    for key in ("limit","per_page","page_size","size"):
        test = {key: "10000"}
        test_url = url_with_params(url, test)
        r = safe_get(test_url, headers=headers, method="GET")
        if r and r.status_code == 200 and len(r.content or b"") > 1_000_000:
            return [("Unrestricted Resource Consumption", f"Large `{key}` accepted; potential data exfil/DoS via big pages.", "MEDIUM")], key
    return [], None

def check_discovery_docs(url, headers):
    base = urlparse(url)
    roots = set()
    # Try root and immediate parent
    roots.add(urlunparse(base._replace(path="/", query="", params="", fragment="")))
    parent_path = "/".join([p for p in base.path.split("/") if p][:-1])
    roots.add(urlunparse(base._replace(path="/"+parent_path, query="", params="", fragment="")))
    candidates = []
    for r in roots:
        for p in ("openapi.json","swagger.json",".well-known/openapi.json","v1/openapi.json"):
            candidates.append(r.rstrip("/") + "/" + p)
    found = []
    for c in candidates:
        r = safe_get(c, headers=headers, method="GET")
        if r and r.status_code == 200 and ("openapi" in r.text or "swagger" in r.text):
            found.append(c)
    issues = []
    if found:
        issues.append(("API Discovery", f"Public OpenAPI/Swagger found: {', '.join(found[:3])}", "INFO"))
    return issues, found

def check_graphql(url, headers):
    # If path already /graphql-like, try introspection; else skip quietly
    if not re.search(r"graphql", url, re.I):
        return [], None
    q = {"query": "{ __schema { queryType { name } } }"}
    r = safe_get(url, headers=headers, method="POST", json_body=q)
    issues = []
    if r and r.status_code == 200 and "__schema" in (r.text or ""):
        issues.append(("GraphQL Introspection", "Introspection enabled in non-dev environment. Disable or lock down.", "MEDIUM"))
    return issues, r.status_code if r else None

def run_all(url, token=None):
    headers = dict(UA)
    if token:
        headers["Authorization"] = f"Bearer {token}"

    report = {
        "target": url,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "findings": [],
        "notes": []
    }

    sections = []

    print("🔍 Starting comprehensive API security scan...")
    
    # Basic checks
    print("🔧 Running basic security checks...")
    basic_issues, first = check_basic(url, headers)
    sections += basic_issues

    # Method checks
    print("🔄 Testing HTTP methods...")
    meth_issues, tested = check_methods(url, headers)
    sections += meth_issues

    # Rate limiting
    print("⏰ Testing rate limiting...")
    rl_issues, _ = check_rate_limit(url, headers)
    sections += rl_issues

    # IDOR
    print("🔓 Testing IDOR/BOLA vulnerabilities...")
    idor_issues, idor_hits = check_idor(url, headers)
    sections += idor_issues

    # Mass assignment
    print("📦 Testing mass assignment...")
    ma_issues, _ = check_mass_assignment(url, headers)
    sections += ma_issues

    # Error handling
    print("❌ Testing error handling...")
    err_issues, _ = check_error_leak(url, headers)
    sections += err_issues

    # Pagination
    print("📄 Testing pagination abuse...")
    pag_issues, _ = check_pagination_abuse(url, headers)
    sections += pag_issues

    # Discovery
    print("📚 Testing API discovery...")
    disc_issues, _ = check_discovery_docs(url, headers)
    sections += disc_issues

    # GraphQL
    print("📊 Testing GraphQL endpoints...")
    gql_issues, _ = check_graphql(url, headers)
    sections += gql_issues

    # Modern vulnerability checks
    print("🔐 Testing JWT vulnerabilities...")
    jwt_issues, _ = check_jwt_vulnerabilities(url, headers)
    sections += jwt_issues

    print("🌐 Testing SSRF vulnerabilities...")
    ssrf_issues, _ = check_ssrf(url, headers)
    sections += ssrf_issues

    print("🛡️ Testing XSS vulnerabilities...")
    xss_issues, _ = check_xss_api(url, headers)
    sections += xss_issues

    print("💉 Testing SQL injection vulnerabilities...")
    sql_issues, _ = check_sql_injection(url, headers)
    sections += sql_issues

    print("🗄️ Testing NoSQL injection vulnerabilities...")
    nosql_issues, _ = check_no_sql_injection(url, headers)
    sections += nosql_issues

    print("💻 Testing command injection vulnerabilities...")
    cmd_issues, _ = check_command_injection(url, headers)
    sections += cmd_issues

    print("📄 Testing XXE vulnerabilities...")
    xxe_issues, _ = check_xxe(url, headers)
    sections += xxe_issues

    print("🚫 Testing broken access control...")
    bac_issues, _ = check_broken_access_control(url, headers)
    sections += bac_issues

    print("🔄 Testing insecure deserialization...")
    deserial_issues, _ = check_insecure_deserialization(url, headers)
    sections += deserial_issues

    print("⚙️ Testing security misconfigurations...")
    misconfig_issues, _ = check_security_misconfiguration(url, headers)
    sections += misconfig_issues

    for cat, msg, severity in sections:
        report["findings"].append({"category": cat, "message": msg, "severity": severity})

    # Hints
    report["notes"].append("Mapped to OWASP API Top 10 (2023): BOLA/IDOR, Broken Auth, Excessive Data Exposure, Lack of Rate Limiting, Mass Assignment, Improper Inventory, etc.")
    return report

def pretty_print(report):
    print(f"\n=== API Guardian Comprehensive Security Report ===")
    print(f"Target : {report['target']}")
    print(f"When   : {report['time']}")
    
    if not report["findings"]:
        print("\n✅ No obvious issues detected with these passive/safe checks.")
    else:
        # Group by severity
        by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
        
        for finding in report["findings"]:
            severity = finding.get("severity", "INFO").upper()
            by_severity[severity].append(finding)
        
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            findings = by_severity[severity]
            if findings:
                color = COLORS.get(severity, COLORS["RESET"])
                print(f"\n{color}🔴 {severity} SEVERITY ISSUES ({len(findings)}){COLORS['RESET']}")
                print("-" * 60)
                for i, finding in enumerate(findings, 1):
                    print(f" {i:02d}. [{finding['category']}] {finding['message']}")
    
    if report["notes"]:
        print(f"\n{COLORS['INFO']}📝 Notes:{COLORS['RESET']}")
        for n in report["notes"]:
            print(f" • {n}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("Usage: python api_guardian.py <api_url> [bearer_token]")
    url = sys.argv[1].strip()
    token = sys.argv[2].strip() if len(sys.argv) > 2 else None
    
    print(f"🚀 Starting security scan for: {url}")
    if token:
        print("🔑 Using provided authentication token")
    
    rep = run_all(url, token)
    pretty_print(rep)
    
    # Also dump JSON (useful for CI)
    with open("api_guardian_report.json","w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)
    print("\n💾 Saved: api_guardian_report.json")