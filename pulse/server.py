"""On-demand localhost HTTP server with automatic idle/window-close shutdown."""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .actions import handle_action
from .live import get_fastfetch_profile, get_live_metrics
from .scanner import HISTORY_FILE, get_latest_or_scan, run_full_scan
from .theme import get_theme_info, get_theme_mtime

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


class ServerState:
    """Track client heartbeat and active scan state for clean auto-shutdown."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.start_time = time.monotonic()
        self.last_heartbeat = time.monotonic()
        self.client_connected = False
        self.active_requests = 0
        self.shutdown_requested_at: float | None = None

    def record_heartbeat(self) -> None:
        with self.lock:
            self.client_connected = True
            self.last_heartbeat = time.monotonic()
            self.shutdown_requested_at = None

    def request_shutdown(self) -> None:
        with self.lock:
            self.shutdown_requested_at = time.monotonic()

    def begin_work(self) -> None:
        with self.lock:
            self.active_requests += 1
            self.last_heartbeat = time.monotonic()

    def end_work(self) -> None:
        with self.lock:
            self.active_requests = max(0, self.active_requests - 1)
            self.last_heartbeat = time.monotonic()


STATE = ServerState()


class PulseRequestHandler(BaseHTTPRequestHandler):
    """Serve static assets and JSON API endpoints on 127.0.0.1."""

    def log_message(self, format: str, *args: Any) -> None:
        # Silence per-request stdout noise
        return

    def _send_json(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_static(self, rel_path: str) -> None:
        if not rel_path or rel_path == "/":
            rel_path = "index.html"
        target = (STATIC_DIR / rel_path.lstrip("/")).resolve()
        if not str(target).startswith(str(STATIC_DIR.resolve())) or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND, "Not Found")
            return

        mime, _ = mimetypes.guess_type(str(target))
        content = target.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", mime or "application/octet-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/heartbeat":
            STATE.record_heartbeat()
            self._send_json({"ok": True, "theme_mtime": get_theme_mtime()})
            return

        if path == "/api/theme":
            STATE.record_heartbeat()
            self._send_json(get_theme_info())
            return

        if path == "/api/live":
            STATE.record_heartbeat()
            qs = parse_qs(parsed.query)
            sort_by = qs.get("sort", ["cpu"])[0]
            self._send_json(get_live_metrics(sort_by=sort_by))
            return

        if path == "/api/report":
            STATE.record_heartbeat()
            STATE.begin_work()
            try:
                report = get_latest_or_scan()
                history: list[Any] = []
                if HISTORY_FILE.is_file():
                    for line in HISTORY_FILE.read_text(encoding="utf-8").splitlines()[-12:]:
                        try:
                            history.append(json.loads(line))
                        except Exception:
                            pass
                self._send_json(
                    {
                        "theme": get_theme_info(),
                        "fastfetch": get_fastfetch_profile(),
                        "report": report,
                        "history": history,
                    }
                )
            finally:
                STATE.end_work()
            return

        STATE.record_heartbeat()
        self._serve_static(path)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/heartbeat":
            STATE.record_heartbeat()
            self._send_json({"ok": True, "theme_mtime": get_theme_mtime()})
            return

        if path == "/api/shutdown":
            STATE.request_shutdown()
            self._send_json({"ok": True})
            return

        length = int(self.headers.get("Content-Length", "0") or 0)
        raw_body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8")) if raw_body else {}
        except Exception:
            payload = {}

        if path == "/api/scan":
            STATE.record_heartbeat()
            STATE.begin_work()
            try:
                report = run_full_scan()
                self._send_json(
                    {
                        "ok": True,
                        "report": report,
                        "theme": get_theme_info(),
                        "fastfetch": get_fastfetch_profile(force_refresh=True),
                    }
                )
            finally:
                STATE.end_work()
            return

        if path == "/api/action":
            STATE.record_heartbeat()
            STATE.begin_work()
            try:
                action_name = str(payload.get("action", ""))
                result = handle_action(action_name, payload)
                self._send_json(result)
            finally:
                STATE.end_work()
            return

        self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")


def _watchdog_loop(server: ThreadingHTTPServer) -> None:
    """Shut down the server automatically when the dashboard window closes."""
    while True:
        time.sleep(1.0)
        now = time.monotonic()
        with STATE.lock:
            if STATE.active_requests > 0:
                continue
            # If window explicitly sent pagehide beacon, allow 1.5s grace for page reload
            if (
                STATE.shutdown_requested_at is not None
                and (now - STATE.shutdown_requested_at) > 1.5
            ):
                break
            # If client connected previously and stopped sending 5s heartbeats for > 12s
            if STATE.client_connected and (now - STATE.last_heartbeat) > 12.0:
                break
            # If never connected within 25s of launch, exit
            if not STATE.client_connected and (now - STATE.start_time) > 25.0:
                break

    server.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Omarchy Pulse on-demand server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (strictly localhost)")
    parser.add_argument("--port", type=int, default=18420, help="Bind port")
    parser.add_argument(
        "--no-watchdog",
        action="store_true",
        help="Disable auto-exit watchdog (for testing)",
    )
    args = parser.parse_args()

    ThreadingHTTPServer.allow_reuse_address = True
    server = ThreadingHTTPServer((args.host, args.port), PulseRequestHandler)

    if not args.no_watchdog:
        t = threading.Thread(target=_watchdog_loop, args=(server,), daemon=True)
        t.start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
