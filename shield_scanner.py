#!/usr/bin/env python3
"""
Shield Scanner - a small web vulnerability scanner for sites YOU own or have
written permission to test.

Passive checks (default):
  - Missing / weak security headers
  - Information-leaking headers (Server, X-Powered-By)
  - Cookie flags (Secure, HttpOnly, SameSite)
  - Form discovery (password over HTTP, missing CSRF token, autocomplete)

Active checks (only with --active):
  - Error-based SQL injection indicators (single-quote probe)
  - Reflected XSS indicators (harmless canary string)

Usage:
  python shield_scanner.py http://localhost:8080
  python shield_scanner.py http://localhost:8080 --active
  python shield_scanner.py https://mysite.com --active --i-own-this --json report.json
"""

import argparse
import ipaddress
import json
import re
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup

USER_AGENT = "ShieldScanner/1.0 (+authorized security testing)"
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

SECURITY_HEADERS = {
    "Content-Security-Policy": ("MEDIUM", "Helps block XSS and data injection.",
                                "Add a Content-Security-Policy header, e.g. default-src 'self'."),
    "Strict-Transport-Security": ("MEDIUM", "Forces browsers to use HTTPS.",
                                  "Add Strict-Transport-Security: max-age=31536000; includeSubDomains."),
    "X-Frame-Options": ("MEDIUM", "Protects against clickjacking.",
                        "Add X-Frame-Options: DENY (or use CSP frame-ancestors)."),
    "X-Content-Type-Options": ("LOW", "Stops MIME-type sniffing.",
                               "Add X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("LOW", "Controls how much referrer data is leaked.",
                        "Add Referrer-Policy: strict-origin-when-cross-origin."),
    "Permissions-Policy": ("LOW", "Restricts browser features like camera and geolocation.",
                           "Add a Permissions-Policy header limiting unused features."),
}

LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql",
    r"mysqli?_",
    r"unclosed quotation mark",
    r"quoted string not properly terminated",
    r"pg_query\(\)|pg::syntaxerror|postgresql.*error",
    r"sqlite[3]?\.operationalerror|sqlite error|sqlite_exception",
    r"microsoft ole db provider for sql server",
    r"odbc sql server driver",
    r"ora-\d{5}",
    r"syntax error at or near",
]
SQL_ERROR_RE = re.compile("|".join(SQL_ERROR_PATTERNS), re.IGNORECASE)

CSRF_FIELD_HINTS = ("csrf", "xsrf", "authenticity_token", "_token", "nonce")

XSS_CANARY = 'shieldxss7731<"\'>'


class Scanner:
    def __init__(self, base_url, active=False, delay=0.5, max_pages=5, timeout=10, verify=True):
        self.base_url = base_url.rstrip("/")
        self.host = urlparse(base_url).netloc
        self.active = active
        self.delay = delay
        self.max_pages = max_pages
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        self.session.verify = verify
        self.findings = []
        self.pages = []
        self.forms_seen = 0

    # ---------- helpers ----------
    def add(self, severity, category, title, detail, fix="", url=""):
        entry = {"severity": severity, "category": category, "title": title,
                 "detail": detail, "fix": fix, "url": url}
        if entry not in self.findings:
            self.findings.append(entry)

    def get(self, url, **kw):
        time.sleep(self.delay)
        try:
            return self.session.get(url, timeout=self.timeout, allow_redirects=True, **kw)
        except requests.RequestException as exc:
            print(f"  [!] Request failed for {url}: {exc}")
            return None

    def post(self, url, data):
        time.sleep(self.delay)
        try:
            return self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
        except requests.RequestException as exc:
            print(f"  [!] POST failed for {url}: {exc}")
            return None

    # ---------- crawl ----------
    def crawl(self):
        print(f"[*] Fetching {self.base_url}")
        first = self.get(self.base_url)
        if first is None:
            return
        self.pages.append((self.base_url, first))
        soup = BeautifulSoup(first.text, "html.parser")
        seen = {self.base_url}
        for a in soup.find_all("a", href=True):
            if len(self.pages) >= self.max_pages:
                break
            link = urljoin(first.url, a["href"]).split("#")[0]
            if urlparse(link).netloc != self.host or link in seen:
                continue
            seen.add(link)
            resp = self.get(link)
            if resp is not None and "text/html" in resp.headers.get("Content-Type", ""):
                self.pages.append((link, resp))
        print(f"[*] Collected {len(self.pages)} page(s) to analyze")

    # ---------- passive checks ----------
    def check_headers(self, url, resp):
        for header, (sev, why, fix) in SECURITY_HEADERS.items():
            if header == "Strict-Transport-Security" and not url.startswith("https"):
                continue
            if header not in resp.headers:
                self.add(sev, "Headers", f"Missing {header}", why, fix, url)
        for header in LEAKY_HEADERS:
            if header in resp.headers:
                self.add("INFO", "Headers", f"{header} header discloses technology",
                         f"{header}: {resp.headers[header]}",
                         f"Remove or genericize the {header} header.", url)

    def check_cookies(self, url, resp):
        try:
            cookies = resp.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            cookies = []
        for c in cookies:
            name = c.split("=", 1)[0]
            low = c.lower()
            if url.startswith("https") and "secure" not in low:
                self.add("MEDIUM", "Cookies", f"Cookie '{name}' missing Secure flag",
                         "Cookie can be sent over unencrypted connections.",
                         "Add the Secure attribute.", url)
            if "httponly" not in low:
                self.add("MEDIUM", "Cookies", f"Cookie '{name}' missing HttpOnly flag",
                         "JavaScript can read this cookie, making XSS more damaging.",
                         "Add the HttpOnly attribute.", url)
            if "samesite" not in low:
                self.add("LOW", "Cookies", f"Cookie '{name}' missing SameSite attribute",
                         "Cookie is sent on cross-site requests, increasing CSRF risk.",
                         "Add SameSite=Lax or Strict.", url)

    def parse_forms(self, url, resp):
        soup = BeautifulSoup(resp.text, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = urljoin(resp.url, form.get("action") or resp.url)
            method = (form.get("method") or "get").lower()
            inputs = []
            for el in form.find_all(["input", "textarea", "select"]):
                name = el.get("name")
                if not name:
                    continue
                inputs.append({"name": name, "type": (el.get("type") or "text").lower(),
                               "value": el.get("value") or ""})
            forms.append({"action": action, "method": method, "inputs": inputs})
        return forms

    def check_forms(self, url, forms):
        for f in forms:
            self.forms_seen += 1
            names = [i["name"].lower() for i in f["inputs"]]
            types = [i["type"] for i in f["inputs"]]
            if "password" in types and f["action"].startswith("http://"):
                self.add("HIGH", "Forms", "Password field submits over HTTP",
                         f"Form posts to {f['action']} without encryption.",
                         "Serve the site over HTTPS and submit forms to https:// URLs.", url)
            if f["method"] == "post" and not any(h in n for n in names for h in CSRF_FIELD_HINTS):
                self.add("MEDIUM", "Forms", "POST form has no visible CSRF token",
                         f"Form to {f['action']} has no field resembling a CSRF token.",
                         "Add a per-session CSRF token and validate it server-side.", url)
            if "password" in types and f["method"] == "get":
                self.add("HIGH", "Forms", "Password field submitted via GET",
                         "Credentials would appear in URLs, logs and browser history.",
                         "Use method=\"post\" for forms containing passwords.", url)
            self.add("INFO", "Forms", f"Form discovered ({f['method'].upper()})",
                     f"Action: {f['action']} | Fields: {', '.join(i['name'] for i in f['inputs']) or 'none'}",
                     "", url)

    # ---------- active checks ----------
    def probe_param_url(self, url, param, payload):
        parts = urlparse(url)
        q = parse_qs(parts.query, keep_blank_values=True)
        q[param] = [payload]
        new = parts._replace(query=urlencode(q, doseq=True))
        return self.get(urlunparse(new))

    def analyze_response(self, url, where, text, payload_kind, baseline_text):
        if payload_kind == "sqli":
            if SQL_ERROR_RE.search(text) and not SQL_ERROR_RE.search(baseline_text):
                self.add("HIGH", "SQL Injection", f"Possible SQL injection in {where}",
                         "A database error message appeared after sending a single quote.",
                         "Use parameterized queries / prepared statements and hide DB errors.", url)
        elif payload_kind == "xss":
            if XSS_CANARY in text:
                self.add("HIGH", "XSS", f"Reflected input not escaped in {where}",
                         "Special characters (< > \" ') came back unencoded in the response.",
                         "HTML-encode output, validate input, and add a strict CSP.", url)

    def active_scan(self):
        print("[*] Running active checks (SQLi / XSS indicators)")
        for url, resp in self.pages:
            # URL query parameters
            params = parse_qs(urlparse(url).query, keep_blank_values=True)
            for p in params:
                for kind, payload in (("sqli", "'"), ("xss", XSS_CANARY)):
                    r = self.probe_param_url(url, p, payload)
                    if r is not None:
                        self.analyze_response(url, f"URL parameter '{p}'", r.text, kind, resp.text)
            # Forms
            for f in self.parse_forms(url, resp):
                testable = [i for i in f["inputs"]
                            if i["type"] in ("text", "search", "email", "url", "tel", "textarea", "")]
                for target in testable:
                    for kind, payload in (("sqli", "'"), ("xss", XSS_CANARY)):
                        data = {i["name"]: (i["value"] or "test") for i in f["inputs"]}
                        data[target["name"]] = payload
                        if f["method"] == "post":
                            r = self.post(f["action"], data)
                        else:
                            r = self.get(f["action"], params=data)
                        if r is not None:
                            self.analyze_response(f["action"], f"form field '{target['name']}'",
                                                  r.text, kind, resp.text)

    # ---------- run ----------
    def run(self):
        self.crawl()
        for url, resp in self.pages:
            self.check_headers(url, resp)
            self.check_cookies(url, resp)
            self.check_forms(url, self.parse_forms(url, resp))
        if self.active:
            self.active_scan()
        else:
            print("[*] Passive mode: skipping SQLi/XSS probes (use --active to enable)")
        return self.findings


def is_local_target(url):
    host = urlparse(url).hostname or ""
    if host in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except ValueError:
        return host.endswith(".local") or host.endswith(".lan")


def print_report(target, findings, pages, forms_seen):
    findings = sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])
    print("\n" + "=" * 70)
    print(f" SHIELD SCAN REPORT - {target}")
    print(f" {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | "
          f"{pages} page(s) | {forms_seen} form(s)")
    print("=" * 70)
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITY_ORDER}
    print(" Summary: " + ", ".join(f"{s}: {n}" for s, n in counts.items()))
    print("-" * 70)
    for f in findings:
        print(f"\n[{f['severity']}] {f['title']}  ({f['category']})")
        print(f"  URL: {f['url']}")
        print(f"  Detail: {f['detail']}")
        if f["fix"]:
            print(f"  Fix: {f['fix']}")
    print("\n" + "=" * 70)


def main():
    ap = argparse.ArgumentParser(description="Shield Scanner - basic web vulnerability scanner")
    ap.add_argument("url", help="Target URL, e.g. http://localhost:8080")
    ap.add_argument("--active", action="store_true", help="Enable SQLi/XSS probes")
    ap.add_argument("--i-own-this", action="store_true",
                    help="Confirm you own or have permission to test a non-local target")
    ap.add_argument("--max-pages", type=int, default=5, help="Max same-site pages to analyze")
    ap.add_argument("--delay", type=float, default=0.5, help="Seconds between requests")
    ap.add_argument("--json", metavar="FILE", help="Save findings to a JSON file")
    ap.add_argument("--insecure", action="store_true", help="Skip TLS certificate verification")
    args = ap.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "http://" + args.url

    if args.active and not is_local_target(args.url) and not args.i_own_this:
        print("Refusing active scan on a non-local target without --i-own-this.\n"
              "Only scan systems you own or have written permission to test.")
        sys.exit(1)

    scanner = Scanner(args.url, active=args.active, delay=args.delay,
                      max_pages=args.max_pages, verify=not args.insecure)
    findings = scanner.run()
    print_report(args.url, findings, len(scanner.pages), scanner.forms_seen)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({"target": args.url,
                       "scanned_at": datetime.now(timezone.utc).isoformat(),
                       "findings": findings}, fh, indent=2)
        print(f"[*] Saved JSON report to {args.json}")


if __name__ == "__main__":
    main()
