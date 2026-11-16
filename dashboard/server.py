#!/usr/bin/env python3
"""
AegisSec: Dashboard Web Server
A lightweight, zero-dependency HTTP server that serves the security control room
and provides JSON APIs to fetch reports and trigger on-demand scans.
"""

import http.server
import socketserver
import os
import json
import sys

# Add parent directory to path so we can import the scanner engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from engine.scanner import run_full_scan

PORT = 8080
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENGINE_DIR = os.path.join(os.path.dirname(BASE_DIR), "engine")
TARGET_DIR = os.path.join(os.path.dirname(BASE_DIR), "target_app")
REPORT_PATH = os.path.join(ENGINE_DIR, "scan_report.json")


class AegisDashboardHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # API: Return the latest scan report
        if self.path == "/api/report":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()

            if os.path.exists(REPORT_PATH):
                with open(REPORT_PATH, "r", encoding="utf-8") as f:
                    data = f.read()
                self.wfile.write(data.encode("utf-8"))
            else:
                # If report does not exist yet, generate it on the fly
                report = run_full_scan(TARGET_DIR)
                self.wfile.write(json.dumps(report).encode("utf-8"))
            return

        # Serve index.html for root path
        if self.path == "/" or self.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_path = os.path.join(BASE_DIR, "index.html")
            with open(html_path, "rb") as f:
                self.wfile.write(f.read())
            return

        # Fallback to standard static file serving
        return super().do_GET()

    def do_POST(self):
        # API: Trigger a fresh scan
        if self.path == "/api/scan":
            report = run_full_scan(TARGET_DIR)

            # Persist updated report
            with open(REPORT_PATH, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(report).encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()


def run_server():
    os.chdir(BASE_DIR)
    # Enable address reuse so restarts don't hit "Address already in use"
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), AegisDashboardHandler) as httpd:
        print("=" * 60)
        print(f"🛡️  AEGIS-SEC DASHBOARD ACTIVE")
        print(f"👉 Local URL: http://localhost:{PORT}")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server...")
            httpd.server_close()


if __name__ == "__main__":
    run_server()
