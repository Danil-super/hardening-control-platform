"""Local HTTP bridge for Hardening Control Platform Agent.

Run this server on the audited Linux host, then the web UI can request
read-only audit JSON from http://127.0.0.1:8765.
"""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

from agent import run_audit

ALLOWED_PROFILES = {"basic_linux", "ssh_security", "web_server", "docker_host"}


class AgentRequestHandler(BaseHTTPRequestHandler):
    server_version = "HCPAgentBridge/0.1"

    def log_message(self, format: str, *args: object) -> None:
        print(f"[agent-bridge] {self.address_string()} - {format % args}")

    def add_cors_headers(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "600")

    def write_json(self, payload: object, status: HTTPStatus = HTTPStatus.OK) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.add_cors_headers()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self.add_cors_headers()
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            self.write_json({"status": "ok", "service": "hcp-agent-bridge", "version": "0.1.0"})
            return

        if parsed.path == "/profiles":
            self.write_json({"profiles": sorted(ALLOWED_PROFILES)})
            return

        if parsed.path == "/audit":
            params = parse_qs(parsed.query)
            profile = params.get("profile", ["basic_linux"])[0]
            include_lynis = parse_bool(params.get("includeLynis", ["false"])[0])
            self.handle_audit(profile, include_lynis=include_lynis)
            return

        self.write_json({"error": "not_found", "message": "Unknown endpoint"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != "/audit":
            self.write_json({"error": "not_found", "message": "Unknown endpoint"}, HTTPStatus.NOT_FOUND)
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length).decode("utf-8") if length else "{}"
            body = json.loads(raw_body)
        except (ValueError, json.JSONDecodeError):
            self.write_json({"error": "bad_request", "message": "Invalid JSON body"}, HTTPStatus.BAD_REQUEST)
            return

        profile = str(body.get("profileId") or body.get("profile") or "basic_linux")
        include_lynis = parse_body_bool(body.get("includeLynis", body.get("lynis", False)))
        self.handle_audit(profile, include_lynis=include_lynis)

    def handle_audit(self, profile: str, include_lynis: bool = False) -> None:
        if profile not in ALLOWED_PROFILES:
            self.write_json(
                {
                    "error": "bad_profile",
                    "message": f"Unsupported profile: {profile}",
                    "allowedProfiles": sorted(ALLOWED_PROFILES),
                },
                HTTPStatus.BAD_REQUEST,
            )
            return

        self.write_json(run_audit(profile, include_lynis=include_lynis))


def parse_bool(value: str) -> bool:
    return value.lower() in {"1", "true", "yes", "on"}


def parse_body_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return parse_bool(value)
    return bool(value)


def main() -> None:
    parser = argparse.ArgumentParser(description="Hardening Control Platform local agent bridge")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), AgentRequestHandler)
    print(f"Hardening Control Platform Agent Bridge listening on http://{args.host}:{args.port}")
    print("Endpoints: GET /health, GET /profiles, GET /audit?profile=basic_linux, POST /audit")
    print("Optional Lynis: GET /audit?profile=basic_linux&includeLynis=1")
    print("Press Ctrl+C to stop the bridge.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nAgent Bridge stopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
