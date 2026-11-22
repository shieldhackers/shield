#!/usr/bin/env python3
"""
Shield launcher - serves the Shield website locally and can scan it.

Put this file in the same folder as index.html, style.css and shield_scanner.py.

Usage:
  python launch.py                  # serve the site at http://localhost:8000 and open the browser
  python launch.py --scan           # serve the site, run a passive scan, save report.json
  python launch.py --scan --secure  # same, but the server sends security headers (compare results)
  python launch.py --port 9000 --no-browser
"""

import argparse
import functools
import http.server
import os
import socketserver
import subprocess
import sys
import threading
import time
import webbrowser

HERE = os.path.dirname(os.path.abspath(__file__))

SECURE_HEADERS = {
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


class ShieldHandler(http.server.SimpleHTTPRequestHandler):
    secure = False

    def end_headers(self):
        if self.secure:
            for name, value in SECURE_HEADERS.items():
                self.send_header(name, value)
        super().end_headers()

    def log_message(self, fmt, *args):
        pass  # keep the terminal quiet


def start_server(port, secure):
    ShieldHandler.secure = secure
    handler = functools.partial(ShieldHandler, directory=HERE)
    socketserver.TCPServer.allow_reuse_address = True
    httpd = socketserver.TCPServer(("127.0.0.1", port), handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd


def run_scan(url, report_name):
    scanner = os.path.join(HERE, "shield_scanner.py")
    if not os.path.exists(scanner):
        print("[!] shield_scanner.py not found in this folder.")
        return
    report_path = os.path.join(HERE, report_name)
    print(f"\n[*] Running Shield Scanner on {url}\n")
    result = subprocess.run([sys.executable, scanner, url, "--json", report_path])
    if result.returncode != 0:
        print("[!] Scanner exited with an error. Did you run: pip install requests beautifulsoup4 ?")


def main():
    ap = argparse.ArgumentParser(description="Serve the Shield site locally and optionally scan it")
    ap.add_argument("--port", type=int, default=8000, help="Port to serve on (default 8000)")
    ap.add_argument("--scan", action="store_true", help="Run shield_scanner.py against the local site")
    ap.add_argument("--secure", action="store_true",
                    help="Send security headers from the local server (for before/after comparison)")
    ap.add_argument("--report", default="report.json", help="Scan report filename")
    ap.add_argument("--no-browser", action="store_true", help="Do not open the browser automatically")
    args = ap.parse_args()

    if not os.path.exists(os.path.join(HERE, "index.html")):
        print("[!] index.html not found. Put launch.py in the same folder as your site files.")
        sys.exit(1)

    url = f"http://localhost:{args.port}"
    try:
        httpd = start_server(args.port, args.secure)
    except OSError:
        print(f"[!] Port {args.port} is busy. Try: python launch.py --port 9000")
        sys.exit(1)

    mode = "with security headers" if args.secure else "default headers"
    print(f"[*] Shield site running at {url} ({mode})")

    if not args.no_browser:
        webbrowser.open(url)

    if args.scan:
        time.sleep(1)
        run_scan(url, args.report)

    print("\n[*] Press Ctrl+C to stop the server.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Stopping server.")
        httpd.shutdown()


if __name__ == "__main__":
    main()
