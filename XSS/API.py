#!/usr/bin/env python3
"""
api_vuln_scanner.py
Safe, lightweight API endpoint scanner (non-destructive).
Only for authorized testing.
"""
import argparse
import asyncio
import csv
import ssl
import socket
from datetime import datetime
from urllib.parse import urljoin, urlparse

import aiohttp

# ---- Configurable checks ----
SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "strict-transport-security",
]
TIMEOUT = aiohttp.ClientTimeout(total=15)


# ---- Helper: TLS expiry check (connects to host:port) ----
def get_tls_expiry(host: str, port: int = 443, timeout: int = 5):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                # 'notAfter' is like 'Jun  1 12:00:00 2025 GMT'
                not_after = cert.get("notAfter")
                if not_after:
                    dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                    return dt
    except Exception:
        return None


# ---- Single endpoint check ----
async def check_endpoint(session: aiohttp.ClientSession, base: str, path: str, headers: dict):
    url = urljoin(base, path.lstrip("/"))
    result = {
        "path": path,
        "url": url,
        "status": None,
        "methods": None,
        "cors_wildcard": False,
        "missing_security_headers": [],
        "accepts_unauthenticated": None,
        "tls_expires": None,
        "error": None,
    }

    try:
        # HEAD first (faster for status-only endpoints)
        async with session.head(url, headers=headers, allow_redirects=True) as resp:
            result["status"] = resp.status
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}

            # CORS check
            acao = resp_headers.get("access-control-allow-origin")
            if acao and acao.strip() == "*":
                result["cors_wildcard"] = True

            # Security headers
            missing = [h for h in SECURITY_HEADERS if h not in resp_headers]
            result["missing_security_headers"] = missing

            # Allowed methods via OPTIONS if provided
            async with session.options(url, headers=headers) as opt:
                allow = opt.headers.get("Allow") or opt.headers.get("allow")
                if allow:
                    result["methods"] = [m.strip() for m in allow.split(",")]

        # Quick unauthenticated check:
        # Send a GET with no Authorization header and see if we get 2xx.
        # This is a *simple* signal — not definitive. Use only for reporting.
        async with session.get(url, headers={}, allow_redirects=True) as unauth_resp:
            result["accepts_unauthenticated"] = 200 <= unauth_resp.status < 300

    except aiohttp.ClientResponseError as e:
        result["error"] = f"HTTP error: {e}"
        result["status"] = getattr(e, "status", None)
    except asyncio.TimeoutError:
        result["error"] = "timeout"
    except Exception as exc:
        result["error"] = str(exc)

    # TLS expiry (use host from base url)
    parsed = urlparse(url)
    if parsed.scheme in ("https", ""):
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        expiry = get_tls_expiry(host, port)
        result["tls_expires"] = expiry.isoformat() if expiry else None

    return result


# ---- Orchestrator ----
async def run_scan(base: str, paths: list, concurrency: int = 20, user_agent: str = None):
    headers = {}
    if user_agent:
        headers["User-Agent"] = user_agent

    connector = aiohttp.TCPConnector(ssl=False)  # don't fail on self-signed in staging; still returns cert info separately
    async with aiohttp.ClientSession(timeout=TIMEOUT, connector=connector) as session:
        sem = asyncio.Semaphore(concurrency)
        tasks = []

        async def sem_task(p):
            async with sem:
                return await check_endpoint(session, base, p, headers)

        for p in paths:
            tasks.append(asyncio.create_task(sem_task(p)))

        results = await asyncio.gather(*tasks)
        return results


# ---- CLI & main ----
def load_paths_from_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def save_csv(results: list, csv_path: str):
    keys = ["path", "url", "status", "methods", "cors_wildcard", "missing_security_headers", "accepts_unauthenticated", "tls_expires", "error"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            row = {k: r.get(k) for k in keys}
            # convert lists to strings
            row["methods"] = ",".join(row["methods"]) if row.get("methods") else ""
            row["missing_security_headers"] = ",".join(row["missing_security_headers"]) if row.get("missing_security_headers") else ""
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(description="Safe API endpoint scanner (non-destructive). Use only with permission.")
    parser.add_argument("base_url", help="Base URL of the API (e.g., https://api.example.com/)")
    parser.add_argument("-w", "--wordlist", help="File with newline-separated paths to test (e.g., /users, /login)")
    parser.add_argument("-c", "--concurrency", type=int, default=20)
    parser.add_argument("-o", "--output", default="api_scan_results.csv")
    parser.add_argument("--user-agent", default="api-vuln-scanner/0.1")
    args = parser.parse_args()

    if not args.wordlist:
        print("Provide a wordlist of paths with -w. Example file: paths.txt")
        return

    paths = load_paths_from_file(args.wordlist)

    print(f"[+] Starting scan of {len(paths)} paths against {args.base_url}")
    results = asyncio.run(run_scan(args.base_url, paths, concurrency=args.concurrency, user_agent=args.user_agent))

    # Print summary lines for quick triage
    for r in results:
        flags = []
        if r["cors_wildcard"]:
            flags.append("CORS:*")
        if r["missing_security_headers"]:
            flags.append("missing-sec-headers")
        if r["accepts_unauthenticated"]:
            flags.append("accepts-unauth")
        if r["tls_expires"] is None:
            flags.append("no-tls-info")
        if r["status"] and 500 <= r["status"] < 600:
            flags.append("server-error")
        if r["error"]:
            flags.append(f"err={r['error']}")

        flag_str = ", ".join(flags) if flags else "ok"
        print(f"{r['status'] or '-'} {r['path']} -> {flag_str}")

    save_csv(results, args.output)
    print(f"[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
