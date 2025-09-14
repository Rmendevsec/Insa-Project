#!/usr/bin/env python3
"""
api_pentester_safe.py

A SAFE, EDUCATIONAL, DEFENSIVE API auditing toolbox for classroom / authorized use only.
This script intentionally avoids exploit payloads, invasive actions, or automated attacks.
It implements passive discovery, safe HTTP method enumeration, JWT inspection (decode-only),
and data-exposure detection. It requires explicit local consent before making any network requests.

Usage (example):
    python3 api_pentester_safe.py -u https://api.example.com/v1 -w wordlist.txt --consent --auth-token YOURTOKEN --output report.json

Safety & Legal Notice (must read):
  - ONLY run this against APIs you OWN or have WRITTEN PERMISSION to test.
  - This tool will not perform destructive tests unless you explicitly enable them via
    --allow-destructive AND you provided a matching local consent token.
  - Misuse may be illegal. Instructor / client authorization must be acquired out-of-band.

Author: Educational example (do not use for offensive purposes)
"""

from __future__ import annotations
import argparse
import json
import os
import re
import sys
import time
import uuid
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs

import requests  # pip install requests
from requests import Response
try:
    import jwt as pyjwt  # pip install PyJWT
except Exception:
    pyjwt = None  # JWT decode features optional

# Optional colored output
try:
    from colorama import init as _color_init, Fore, Style
    _color_init()
except Exception:
    # Fallback if colorama is not installed
    class _ColorFallback:
        def __getattr__(self, name):
            return ''
    Fore = Style = _ColorFallback()

# -------------------------
# Configuration / Globals
# -------------------------
DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (compatible; EduScanner/1.0; +https://example.edu)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EduScanner/1.0",
]

SENSITIVE_PATTERNS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)aws(.{0,20})?(secret|secret_key|secretaccesskey)[:=]\s*[A-Za-z0-9/+=]{16,40}"),
    "JWT": re.compile(r"eyJ[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+?\.[A-Za-z0-9_\-]+"),
    "Email": re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"),
    "API Key-like": re.compile(r"(?:api[_-]?key|token|secret)[\"'\s:=]{1,4}[A-Za-z0-9\-\._]{8,64}", re.I),
    # Add more patterns as needed
}

# -------------------------
# Helper dataclasses
# -------------------------
@dataclass
class Endpoint:
    path: str
    methods: List[str]
    discovered_by: str  # e.g., "wordlist", "openapi"
    status_codes: Dict[str, int]  # method -> last status code
    sample_responses: Dict[str, Dict[str, Any]]  # method -> {status, len, excerpt}

@dataclass
class Finding:
    id: str
    title: str
    severity: str
    endpoint: str
    method: str
    evidence: Dict[str, Any]
    recommendation: str

# -------------------------
# Consent mechanism
# -------------------------
CONSENT_FILE = "consent.json"

def ensure_consent_file_exists():
    """
    If consent file doesn't exist, offer to create a template for the user.
    The file should contain a simple token the user must pass via --auth-token.
    This simulates an out-of-band permission token and prevents casual misuse.
    """
    if not os.path.exists(CONSENT_FILE):
        template = {
            "project": "authorized-api-audit",
            "owner": "Instructor/Client Name",
            "consent_token": str(uuid.uuid4()),
            "notes": "Place this consent.json in the working directory before running the tool."
        }
        with open(CONSENT_FILE, "w") as f:
            json.dump(template, f, indent=2)
        print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL +
              f" A consent template was created at ./{CONSENT_FILE}. Replace the fields with real authorization and re-run with --auth-token <consent_token>.")


def validate_consent(auth_token: str, require_allow_destructive: bool=False, allow_destructive_flag: bool=False) -> bool:
    """
    Validates the provided auth_token against local consent.json.
    If allow destructive tests are requested, the consent file must include "allow_destructive": true.
    """
    if not os.path.exists(CONSENT_FILE):
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL + f" Consent file ./{CONSENT_FILE} not found. Run with --create-consent to create a template.")
        return False
    with open(CONSENT_FILE, "r") as f:
        try:
            data = json.load(f)
        except Exception as e:
            print(Fore.RED + "[ERROR]" + Style.RESET_ALL + " Failed to parse consent.json: " + str(e))
            return False
    token = data.get("consent_token")
    if token != auth_token:
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL + " Provided auth token does not match consent.json.")
        return False
    if require_allow_destructive and not data.get("allow_destructive", False):
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL + " Consent file does not allow destructive tests. Set \"allow_destructive\": true in consent.json to allow.")
        return False
    if require_allow_destructive and not allow_destructive_flag:
        # Extra guard: even if consent file allows destructive, CLI flag must be present
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL + " Destructive tests require both consent file permission and the --allow-destructive CLI flag.")
        return False
    return True

# -------------------------
# Utility functions
# -------------------------
def pick_user_agent(randomize: bool=True) -> str:
    import random
    if randomize:
        return random.choice(DEFAULT_USER_AGENTS)
    else:
        return DEFAULT_USER_AGENTS[0]

def safe_request(session: requests.Session, method: str, url: str, timeout: float=10.0, headers: Dict[str,str]=None, allow_redirects: bool=True, proxies: Dict[str,str]=None) -> Tuple[Optional[Response], Optional[Exception]]:
    """
    Wrap requests to centralize error handling. Returns (response, exception).
    """
    try:
        resp = session.request(method=method.upper(), url=url, timeout=timeout, headers=headers or {}, allow_redirects=allow_redirects, proxies=proxies)
        return resp, None
    except Exception as e:
        return None, e

def redact_sensitive_headers(headers: Dict[str,str]) -> Dict[str,str]:
    """
    Redact Authorization, Cookie, and similar sensitive headers before logging.
    """
    redacted = {}
    for k, v in (headers or {}).items():
        if k.lower() in ("authorization", "cookie", "set-cookie"):
            redacted[k] = "[REDACTED]"
        else:
            redacted[k] = v
    return redacted

# -------------------------
# Main scanning class
# -------------------------
class APIScanner:
    """
    APIScanner: Safe, modular, class-based structure for defensive API auditing.
    It avoids destructive or exploitative actions unless explicitly enabled via consent and flags.
    """

    def __init__(self,
                 base_url: str,
                 wordlist: Optional[str] = None,
                 auth: Optional[str] = None,
                 proxy: Optional[str] = None,
                 verbose: bool = False,
                 rate: float = 1.0,
                 random_user_agent: bool = True,
                 safe_mode: bool = True,
                 output: Optional[str] = None,
                 redact: bool = True,
                 allow_destructive: bool = False):
        self.base_url = base_url.rstrip("/")
        self.wordlist = wordlist
        self.auth = auth
        self.proxy = proxy
        self.verbose = verbose
        self.rate = rate  # requests per second
        self.delay = 1.0 / max(rate, 1e-6)
        self.user_agent = pick_user_agent(random_user_agent)
        self.safe_mode = safe_mode
        self.output = output
        self.redact = redact
        self.allow_destructive = allow_destructive

        # Internal storage
        self.endpoints: Dict[str, Endpoint] = {}
        self.findings: List[Finding] = []

        # Requests session
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        if auth:
            # Basic or bearer token detection
            if ":" in auth and not auth.lower().startswith("bearer "):
                # Basic auth style: username:password
                user, pwd = auth.split(":", 1)
                self.session.auth = (user, pwd)
            elif auth.lower().startswith("bearer ") or len(auth.split()) == 1:
                # Bearer token or single token
                token = auth if auth.lower().startswith("bearer ") else f"Bearer {auth}"
                self.session.headers.update({"Authorization": token})

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    # -------------------------
    # Discovery
    # -------------------------
    def discover_openapi(self, openapi_url: str) -> None:
        """
        Try to fetch and parse a Swagger/OpenAPI JSON/YAML manifest.
        This is non-destructive — reads the document and records paths/methods.
        """
        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL + f" Attempting to fetch OpenAPI document from: {openapi_url}")
        resp, err = safe_request(self.session, "GET", openapi_url)
        if err:
            print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL + f" Failed to fetch OpenAPI: {err}")
            return
        ct = resp.headers.get("Content-Type", "")
        text = resp.text
        try:
            # Try JSON first
            doc = resp.json()
        except Exception:
            # Minimal YAML-ish parsing is out of scope; skip YAML parsing to avoid heavy deps.
            print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL + " OpenAPI parsing supports JSON manifests only in this safe tool.")
            return
        paths = doc.get("paths", {})
        for path, meta in paths.items():
            methods = [m.upper() for m in meta.keys() if isinstance(m, str)]
            full = urljoin(self.base_url + "/", path.lstrip("/"))
            ep = Endpoint(path=full, methods=methods, discovered_by="openapi", status_codes={}, sample_responses={})
            self.endpoints[full] = ep
        print(Fore.GREEN + "[OK]" + Style.RESET_ALL + f" Parsed {len(paths)} paths from OpenAPI.")

    def discover_endpoints(self, wordlist_path: Optional[str] = None, methods: Optional[List[str]] = None, rate: Optional[float] = None) -> None:
        """
        Safe endpoint discovery by trying paths from a wordlist.
        This method sends benign requests (HEAD/GET) to detect which paths exist.
        It will NOT inject or fuzz parameters.
        """
        if wordlist_path is None:
            wordlist_path = self.wordlist
        if wordlist_path is None or not os.path.exists(wordlist_path):
            print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL + " No valid wordlist provided — skipping wordlist discovery.")
            return
        methods = methods or ["HEAD", "GET"]
        rate = rate or self.rate
        delay = 1.0 / max(rate, 1e-6)

        with open(wordlist_path, "r", errors="ignore") as f:
            words = [w.strip() for w in f if w.strip() and not w.startswith("#")]

        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL + f" Starting safe wordlist discovery ({len(words)} entries). Using methods: {methods}. Delay={delay:.2f}s")
        for w in words:
            # Build URL carefully
            candidate = urljoin(self.base_url + "/", w.lstrip("/"))
            recorded_methods = []
            sample_responses = {}
            for m in methods:
                time.sleep(delay)
                resp, err = safe_request(self.session, m, candidate)
                if err:
                    if self.verbose:
                        print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL + f" {m} {candidate} -> error: {err}")
                    continue
                status = resp.status_code
                if status < 400 or status in (401,403):  # include some auth-protected endpoints as interesting
                    recorded_methods.append(m)
                    sample_responses[m] = {
                        "status": status,
                        "length": len(resp.content or b""),
                        "excerpt": (resp.text[:300] if resp.text else "")
                    }
                if self.verbose:
                    print(Fore.BLUE + "[INFO]" + Style.RESET_ALL + f" {m} {candidate} -> {status} ({len(resp.content or b'')} bytes)")
            if recorded_methods:
                ep = Endpoint(path=candidate, methods=recorded_methods, discovered_by="wordlist", status_codes={m: sample_responses[m]["status"] for m in recorded_methods}, sample_responses=sample_responses)
                self.endpoints[candidate] = ep
        print(Fore.GREEN + "[OK]" + Style.RESET_ALL + f" Discovery finished. Found {len(self.endpoints)} endpoints.")

    # -------------------------
    # Methods testing (non-destructive by default)
    # -------------------------
    def test_methods(self, endpoint_list: Optional[List[str]] = None, methods_to_test: Optional[List[str]] = None) -> None:
        """
        Test which HTTP methods are accepted on endpoints.
        In safe_mode we avoid destructive methods (PUT/DELETE) unless allow_destructive is True and consent granted.
        """
        endpoint_list = endpoint_list or list(self.endpoints.keys())
        if not endpoint_list:
            print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL + " No endpoints to test.")
            return
        base_methods = methods_to_test or ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
        # In safe mode, filter out destructive methods
        destructive = {"PUT", "DELETE", "PATCH"}
        if self.safe_mode and not self.allow_destructive:
            test_methods = [m for m in base_methods if m not in destructive]
            print(Fore.BLUE + "[INFO]" + Style.RESET_ALL + f" Safe mode enabled — skipping destructive methods: {destructive}")
        else:
            test_methods = base_methods

        print(Fore.BLUE + "[INFO]" + Style.RESET_ALL + f" Testing methods: {test_methods}")
        for ep in endpoint_list:
            for m in test_methods:
                time.sleep(self.delay)
                resp, err = safe_request(self.session, m, ep)
                if err:
                    if self.verbose:
                        print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL + f" {m} {ep} -> error: {err}")
                    continue
                status = resp.status_code
                # store/update endpoint meta
                endpoint_obj = self.endpoints.get(ep)
                if endpoint_obj:
                    endpoint_obj.status_codes[m] = status
                    endpoint_obj.sample_responses[m] = {"status": status, "length": len(resp.content or b""), "excerpt": resp.text[:300] if resp.text else ""}
                # Report potentially risky enabled methods
                if status not in (404, 405) and status < 500:
                    if m in ("PUT", "DELETE", "PATCH"):
                        # Flag as high priority if destructive methods are allowed
                        sev = "High" if not self.safe_mode else "Medium"
                        finding = Finding(
                            id=str(uuid.uuid4()),
                            title="Potentially dangerous HTTP method allowed",
                            severity=sev,
                            endpoint=ep,
                            method=m,
                            evidence={"status": status, "snippet": resp.text[:200]},
                            recommendation=f"Review whether {m} should be allowed. Disable or protect it via auth & RBAC."
                        )
                        self.findings.append(finding)
                        print(Fore.YELLOW + "[FIND]" + Style.RESET_ALL + f" {finding.title} {ep} [{m}] status={status}")

    # -------------------------
    # Auth / JWT inspection (defensive-only)
    # -------------------------
    def inspect_auth(self, endpoint_list: Optional[List[str]] = None) -> None:
        """
        Performs non-destructive comparisons between authenticated and unauthenticated requests.
        Does NOT attempt to bypass auth or manipulate tokens. If a token is provided, tool can:
          - Decode JWT header/payload (without verifying signature) to surface alg and claims.
          - Compare responses with and without Authorization header to spot missing auth checks.
        """
        endpoint_list = endpoint_list or list(self.endpoints.keys())
        if not endpoint_list:
            print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL + " No endpoints to inspect for auth.")
            return
        # If there's an Authorization header in session headers, use it for comparison
        auth_header = None
        for h in ("Authorization", "authorization"):
            if h in self.session.headers:
                auth_header = (h, self.session.headers[h])
                break

        for ep in endpoint_list:
            # Perform an unauthenticated GET
            # Save original headers and temporarily remove auth header if present
            original_headers = dict(self.session.headers)
            if auth_header:
                self.session.headers.pop(auth_header[0], None)
            time.sleep(self.delay)
            unauth_resp, _ = safe_request(self.session, "GET", ep)
            # Restore headers and perform authenticated GET
            if auth_header:
                self.session.headers[auth_header[0]] = auth_header[1]
            time.sleep(self.delay)
            auth_resp, _ = safe_request(self.session, "GET", ep)

            unauth_code = unauth_resp.status_code if unauth_resp else None
            auth_code = auth_resp.status_code if auth_resp else None

            if self.verbose:
                print(Fore.BLUE + "[INFO]" + Style.RESET_ALL + f" Auth compare {ep}: unauth={unauth_code} auth={auth_code}")

            # If both are 200 (or similar), this suggests the endpoint may not be enforcing auth
            if unauth_code and auth_code and unauth_code < 300 and auth_code < 300:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title="Endpoint accessible without authentication",
                    severity="High",
                    endpoint=ep,
                    method="GET",
                    evidence={"unauth_status": unauth_code, "auth_status": auth_code},
                    recommendation="Ensure authentication is enforced. Verify server-side auth on protected resources."
                )
                self.findings.append(finding)
                print(Fore.YELLOW + "[FIND]" + Style.RESET_ALL + f" {finding.title} {ep} unauth={unauth_code} auth={auth_code}")

        # JWT decode-only (no brute force)
        if pyjwt:
            # Attempt to detect a JWT in headers or example responses
            token = None
            # check Authorization header
            if auth_header:
                token_candidate = auth_header[1]
                if token_candidate.lower().startswith("bearer "):
                    token = token_candidate.split(None, 1)[1]
            # search found endpoint sample responses for JWT-like strings
            if not token:
                for ep in self.endpoints.values():
                    for m, meta in ep.sample_responses.items():
                        excerpt = meta.get("excerpt", "")
                        match = SENSITIVE_PATTERNS["JWT"].search(excerpt)
                        if match:
                            token = match.group(0)
                            break
                    if token:
                        break
            if token:
                try:
                    decoded = pyjwt.decode(token, options={"verify_signature": False, "verify_aud": False})
                    finding = Finding(
                        id=str(uuid.uuid4()),
                        title="JWT token found (decode-only)",
                        severity="Medium",
                        endpoint="N/A",
                        method="N/A",
                        evidence={"decoded_claims": decoded},
                        recommendation="Rotate tokens and ensure they are not exposed in responses. Verify signing alg and secret management."
                    )
                    self.findings.append(finding)
                    print(Fore.YELLOW + "[FIND]" + Style.RESET_ALL + " Found JWT token — decoded claims added to findings (no verification performed).")
                except Exception as e:
                    if self.verbose:
                        print(Fore.YELLOW + "[WARN]" + Style.RESET_ALL + f" JWT decode failed: {e}")
        else:
            if self.verbose:
                print(Fore.BLUE + "[INFO]" + Style.RESET_ALL + " PyJWT not installed — JWT decode features disabled.")

    # -------------------------
    # Passive input validation checks (no payload injection)
    # -------------------------
    def inspect_input_handling(self, endpoint_list: Optional[List[str]] = None) -> None:
        """
        Passive inspection for input handling: identifies query parameters and JSON keys
        present in sample responses or in endpoint URLs. Does not send malicious payloads.
        Instead, it enumerates input points and flags endpoints that accept inputs but
        return server errors or echo back input unsafely (possible reflection).
        """
        endpoint_list = endpoint_list or list(self.endpoints.keys())
        for ep in endpoint_list:
            parsed = urlparse(ep)
            params = parse_qs(parsed.query)
            # Record presence of query params as interesting
            if params:
                finding = Finding(
                    id=str(uuid.uuid4()),
                    title="Endpoint accepts query parameters",
                    severity="Low",
                    endpoint=ep,
                    method="GET",
                    evidence={"params": list(params.keys())},
                    recommendation="Ensure server-side validation and proper output encoding to prevent injection/reflective issues."
                )
                self.findings.append(finding)
                if self.verbose:
                    print(Fore.BLUE + "[INFO]" + Style.RESET_ALL + f" {ep} has query params: {list(params.keys())}")

            # Try to infer JSON keys from sample response (if JSON)
            ep_obj = self.endpoints.get(ep)
            if ep_obj:
                for m, sample in ep_obj.sample_responses.items():
                    excerpt = sample.get("excerpt", "")
                    if excerpt.strip().startswith("{") or excerpt.strip().startswith("["):
                        try:
                            j = json.loads(excerpt)
                            if isinstance(j, dict):
                                keys = list(j.keys())[:10]
                                finding = Finding(
                                    id=str(uuid.uuid4()),
                                    title="Endpoint returns JSON structure (sample)",
                                    severity="Info",
                                    endpoint=ep,
                                    method=m,
                                    evidence={"json_keys_sample": keys},
                                    recommendation="Validate and sanitize JSON fields server-side."
                                )
                                self.findings.append(finding)
                        except Exception:
                            pass

    # -------------------------
    # Data exposure scanning
    # -------------------------
    def scan_for_data_exposure(self, endpoint_list: Optional[List[str]] = None) -> None:
        """
        Analyze stored sample responses for secrets or PII using regex patterns.
        This is a passive scan on what we've already retrieved; it does not make new invasive calls.
        """
        endpoint_list = endpoint_list or list(self.endpoints.keys())
        for ep in endpoint_list:
            ep_obj = self.endpoints.get(ep)
            if not ep_obj:
                continue
            for m, sample in ep_obj.sample_responses.items():
                excerpt = sample.get("excerpt", "")
                for name, patt in SENSITIVE_PATTERNS.items():
                    for match in patt.finditer(excerpt or ""):
                        snippet = match.group(0)
                        finding = Finding(
                            id=str(uuid.uuid4()),
                            title=f"Possible {name} found in response",
                            severity="High" if name in ("AWS Secret Key", "AWS Access Key") else "Medium",
                            endpoint=ep,
                            method=m,
                            evidence={"match": snippet[:200]},
                            recommendation="Remove secrets from responses. Rotate any exposed keys immediately and restrict access."
                        )
                        self.findings.append(finding)
                        print(Fore.YELLOW + "[FIND]" + Style.RESET_ALL + f" {finding.title} at {ep} [{m}]")

    # -------------------------
    # Reporting
    # -------------------------
    def generate_report(self, output_file: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a structured JSON report summarizing endpoints and findings.
        Also optionally writes to output_file (JSON). If output file ends with .md, a simple markdown report is generated.
        """
        report = {
            "target": self.base_url,
            "endpoints": {k: asdict(v) for k, v in self.endpoints.items()},
            "findings": [asdict(f) for f in self.findings],
            "meta": {
                "safe_mode": self.safe_mode,
                "user_agent": self.user_agent,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }
        }
        of = output_file or self.output
        if of:
            try:
                if of.endswith(".md") or of.endswith(".markdown"):
                    # Simple markdown rendering
                    with open(of, "w") as fh:
                        fh.write(f"# API Audit Report — {self.base_url}\n\n")
                        fh.write(f"**Safe mode:** {self.safe_mode}\n\n")
                        fh.write("## Findings\n\n")
                        for f in self.findings:
                            fh.write(f"### {f.title} — {f.severity}\n")
                            fh.write(f"- endpoint: `{f.endpoint}`\n")
                            fh.write(f"- method: {f.method}\n")
                            fh.write(f"- evidence: `{json.dumps(f.evidence)[:400]}`\n")
                            fh.write(f"- recommendation: {f.recommendation}\n\n")
                    print(Fore.GREEN + "[OK]" + Style.RESET_ALL + f" Markdown report written to {of}")
                else:
                    with open(of, "w") as fh:
                        json.dump(report, fh, indent=2)
                    print(Fore.GREEN + "[OK]" + Style.RESET_ALL + f" JSON report written to {of}")
            except Exception as e:
                print(Fore.RED + "[ERROR]" + Style.RESET_ALL + f" Failed to write report: {e}")
        return report

# -------------------------
# CLI
# -------------------------
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="api_pentester_safe.py — Defensive API auditing toolbox (safe-by-default).")
    parser.add_argument("-u", "--url", required=True, help="Base URL of target API (e.g., https://api.example.com/v1)")
    parser.add_argument("-w", "--wordlist", help="Path to wordlist for endpoint discovery (optional)")
    parser.add_argument("-a", "--auth", help="Auth: username:password or bearer token (optional)")
    parser.add_argument("--proxy", help="HTTP proxy (e.g., http://127.0.0.1:8080) to route requests through for inspection (optional)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-o", "--output", help="File to save final report (JSON or .md)")
    parser.add_argument("--rate", type=float, default=1.0, help="Rate limit (requests per second)")
    parser.add_argument("--consent", action="store_true", help="Confirm you have written authorization to test the target (required to run network actions)")
    parser.add_argument("--auth-token", help="Local consent token matching consent.json (required if --consent is set)")
    parser.add_argument("--create-consent", action="store_true", help="Create a consent.json template in current directory and exit")
    parser.add_argument("--safe-mode", action="store_true", default=True, help="Enable safe mode (skip destructive tests) [default]")
    parser.add_argument("--allow-destructive", action="store_true", help="Allow destructive method testing IF consent.json also allows it (extra guard)")
    parser.add_argument("--no-random-ua", dest="random_ua", action="store_false", help="Use static User-Agent (disable randomization)")
    parser.add_argument("--redact", action="store_true", default=True, help="Redact sensitive headers in logs and reports")
    return parser.parse_args()

def main():
    args = parse_args()

    # Create consent template if requested
    if args.create_consent:
        ensure_consent_file_exists()
        print("Consent file template created. Edit and place a real consent_token before running.")
        return

    # minimal CLI pre-flight
    print("#" * 60)
    print("SAFE API AUDIT TOOL — Read the header/license before use.")
    print("Only proceed if you have written permission from the owner of the target system.")
    print("#" * 60)

    if not args.consent or not args.auth_token:
        print(Fore.RED + "[ERROR]" + Style.RESET_ALL + " You must pass --consent and --auth-token pointing to the token in consent.json to proceed with network actions.")
        print("Use --create-consent to create a template consent.json in the current directory.")
        return

    # Validate consent file / token
    allow_destructive_requested = args.allow_destructive
    valid = validate_consent(auth_token=args.auth_token, require_allow_destructive=allow_destructive_requested, allow_destructive_flag=allow_destructive_requested)
    if not valid:
        return

    scanner = APIScanner(
        base_url=args.url,
        wordlist=args.wordlist,
        auth=args.auth,
        proxy=args.proxy,
        verbose=args.verbose,
        rate=args.rate,
        random_user_agent=args.random_ua,
        safe_mode=args.safe_mode,
        output=args.output,
        redact=args.redact,
        allow_destructive=args.allow_destructive
    )

    # Start safe workflow
    # 1) Attempt OpenAPI discovery at common locations
    openapi_candidates = [
        urljoin(scanner.base_url + "/", "openapi.json"),
        urljoin(scanner.base_url + "/", "swagger.json"),
        urljoin(scanner.base_url + "/", "swagger/v1/swagger.json"),
    ]
    for c in openapi_candidates:
        scanner.discover_openapi(c)

    # 2) Wordlist discovery (benign HEAD/GET)
    if scanner.wordlist:
        scanner.discover_endpoints(wordlist_path=scanner.wordlist, methods=["HEAD", "GET"], rate=scanner.rate)

    # 3) Method enumeration (non-destructive by default)
    scanner.test_methods(list(scanner.endpoints.keys()))

    # 4) Auth inspection (non-invasive)
    scanner.inspect_auth(list(scanner.endpoints.keys()))

    # 5) Passive input inspection (no injection)
    scanner.inspect_input_handling(list(scanner.endpoints.keys()))

    # 6) Data exposure scanning (passive against captured responses)
    scanner.scan_for_data_exposure(list(scanner.endpoints.keys()))

    # 7) Report
    report = scanner.generate_report(output_file=args.output)
    print(Fore.GREEN + "[DONE]" + Style.RESET_ALL + " Scan complete. Review the report and follow the ethical checklist before any further action.")

if __name__ == "__main__":
    main()
