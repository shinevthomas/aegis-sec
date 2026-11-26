#!/usr/bin/env python3
"""
AegisSec: Advanced ASPM Dashboard Web Server
Lightweight, zero-dependency HTTP server serving the DevSecOps control room
and JSON/SARIF APIs for on-demand multi-project scanning and telemetry.
"""

from datetime import datetime, timezone
import http.server
import json
import os
import socketserver
import sys
from urllib.parse import parse_qs, urlparse

# Add parent directory to path so we can import the scanner engine
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from engine.scanner import run_full_scan, to_sarif

PORT = int(os.environ.get("PORT", "8080"))
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
ENGINE_DIR = os.path.join(ROOT_DIR, "engine")
TARGET_DIR = os.path.join(ROOT_DIR, "target_app")
REPORT_PATH = os.path.join(ENGINE_DIR, "scan_report.json")
HISTORY_PATH = os.path.join(ENGINE_DIR, "scan_history.json")
PROJECTS_ROOT = os.path.expanduser("~/projects")
MAX_HISTORY_ITEMS = 30


def load_json_file(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def save_json_file(path: str, payload) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def get_current_report() -> dict:
    report = load_json_file(REPORT_PATH, None)
    if report is None:
        report = run_full_scan(TARGET_DIR)
        report["scanned_at"] = datetime.now(timezone.utc).isoformat()
        save_json_file(REPORT_PATH, report)
    return report


def append_history(report: dict, threshold: int) -> list:
    history = load_json_file(HISTORY_PATH, [])
    if not isinstance(history, list):
        history = []

    summary = report.get("summary", {})
    score = summary.get("score", 0)
    entry = {
        "timestamp": report.get("scanned_at") or datetime.now(timezone.utc).isoformat(),
        "target": report.get("target_directory", TARGET_DIR),
        "target_name": os.path.basename(report.get("target_directory", TARGET_DIR)) or "target",
        "score": score,
        "grade": summary.get("grade", "N/A"),
        "total_findings": summary.get("total_findings", 0),
        "counts": summary.get("counts", {}),
        "files_scanned": summary.get("files_scanned", 0),
        "scan_duration_ms": summary.get("scan_duration_ms", 0),
        "threshold": threshold,
        "gate_passed": score >= threshold,
    }
    history.insert(0, entry)
    history = history[:MAX_HISTORY_ITEMS]
    save_json_file(HISTORY_PATH, history)
    return history


def discover_projects() -> list:
    projects = [
        {
            "name": "target_app (AegisSec Baseline)",
            "path": TARGET_DIR,
            "kind": "baseline",
        }
    ]
    if os.path.isdir(PROJECTS_ROOT):
        for name in sorted(os.listdir(PROJECTS_ROOT), key=str.lower):
            full_path = os.path.join(PROJECTS_ROOT, name)
            if os.path.isdir(full_path) and not name.startswith("."):
                projects.append(
                    {
                        "name": name,
                        "path": full_path,
                        "kind": "local",
                    }
                )
    return projects


class AegisDashboardHandler(http.server.SimpleHTTPRequestHandler):
    def _send_json(self, status_code: int, payload, filename: str = "") -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/api/report":
            self._send_json(200, get_current_report())
            return

        if path == "/api/history":
            history = load_json_file(HISTORY_PATH, [])
            self._send_json(200, {"history": history})
            return

        if path == "/api/projects":
            self._send_json(200, {"projects": discover_projects()})
            return

        if path == "/api/sarif":
            sarif = to_sarif(get_current_report())
            filename = "aegis-results.sarif" if query.get("download") == ["1"] else ""
            self._send_json(200, sarif, filename=filename)
            return

        if path == "/api/export/json":
            filename = "aegis-report.json" if query.get("download") == ["1"] else ""
            self._send_json(200, get_current_report(), filename=filename)
            return

        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            html_path = os.path.join(BASE_DIR, "index.html")
            with open(html_path, "rb") as f:
                self.wfile.write(f.read())
            return

        return super().do_GET()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path != "/api/scan":
            self._send_json(404, {"error": "Not found"})
            return

        content_len = int(self.headers.get("Content-Length", "0") or 0)
        body_data = {}
        if content_len > 0:
            try:
                raw_body = self.rfile.read(content_len).decode("utf-8")
                body_data = json.loads(raw_body) if raw_body.strip() else {}
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "Invalid JSON request body"})
                return

        requested_target = str(body_data.get("target") or TARGET_DIR).strip()
        target_abs = os.path.abspath(os.path.expanduser(requested_target))
        if not os.path.isdir(target_abs):
            self._send_json(400, {"error": f"Target directory does not exist: {target_abs}"})
            return

        try:
            threshold = int(body_data.get("threshold", 80))
        except (TypeError, ValueError):
            threshold = 80
        threshold = max(0, min(100, threshold))

        report = run_full_scan(target_abs)
        report["scanned_at"] = datetime.now(timezone.utc).isoformat()
        report["threshold"] = threshold
        report["gate_passed"] = report["summary"]["score"] >= threshold

        save_json_file(REPORT_PATH, report)
        history = append_history(report, threshold)
        report["history"] = history

        self._send_json(200, report)


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def run_server():
    os.chdir(BASE_DIR)
    with ReusableTCPServer(("", PORT), AegisDashboardHandler) as httpd:
        print("=" * 60)
        print("🛡️  AEGIS-SEC DASHBOARD ACTIVE")
        print(f"👉 Local URL: http://localhost:{PORT}")
        print("=" * 60)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down dashboard server...")
            httpd.server_close()


if __name__ == "__main__":
    run_server()
