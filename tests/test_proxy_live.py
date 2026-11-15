"""Record real requests through the local mitmproxy."""

import json
import os
import shutil
import socket
import subprocess
import threading
from pathlib import Path

import pytest

import sys

from oby.proxy import Mitm


pytestmark = pytest.mark.skipif(shutil.which("curl") is None, reason="curl is required")


def test_records_example_through_mitm(tmp_path: Path):
    mitm = Mitm(tmp_path / "session")
    mitm.start()
    try:
        result = subprocess.run(
            [
                "curl", "-sS", "--http2", "-o", "/dev/null", "-w", "%{http_code}",
                "--proxy", mitm.server,
                "--cacert", str(mitm.ca_cert),
                "https://example.com/",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=40,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "200"
    finally:
        mitm.stop()

    lines = [
        json.loads(line)
        for line in (tmp_path / "session" / "flows.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    page = next(row for row in lines if row["url"].startswith("https://example.com") and row["status"] == 200)
    assert page["request_headers"]
    assert page["mitmcloak"]["via"] == "mirror"
    assert page["request_http_version"].startswith("HTTP/2")
    assert page["http2"]["settings"]
    assert isinstance(page["http2"]["pseudo_order"], list) and page["http2"]["pseudo_order"]
    assert "proxy-authorization" not in page["request_header_block"].lower()
    assert (tmp_path / "session" / "flows.mitm").exists()


def test_header_order_case_and_duplicates_survive(tmp_path: Path):
    mitm = Mitm(tmp_path / "session")
    mitm.start()
    try:
        sock = socket.create_connection(("127.0.0.1", mitm.port), timeout=20)
        sock.sendall(
            b"GET http://example.com/oby-headers HTTP/1.1\r\n"
            b"Host: example.com\r\n"
            b"X-Odd-Case: 1\r\n"
            b"Cookie: a=1\r\n"
            b"Cookie: b=2\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        while sock.recv(65536):
            pass
        sock.close()
    finally:
        mitm.stop()

    rows = [
        json.loads(line)
        for line in (tmp_path / "session" / "flows.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    match = next(row for row in rows if row["url"].endswith("/oby-headers"))
    block = match["request_header_block"]
    assert "X-Odd-Case: 1\r\nCookie: a=1\r\nCookie: b=2\r\n" in block
    assert "proxy-authorization" not in block.lower()
    # Plain HTTP has no ClientHello, so the TLS preset stays static.
    # exact header mode still forwards this block as sent.
    assert match["mitmcloak"]["via"] == "static"


def test_upstream_receives_order_case_and_duplicate_cookies(tmp_path: Path):
    """The origin, not only the recording, sees the client's header block."""
    received: dict[str, bytes] = {}
    ready = threading.Event()

    def serve() -> None:
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        received["port"] = str(server.getsockname()[1]).encode()
        ready.set()
        server.settimeout(25)
        try:
            conn, _ = server.accept()
        except socket.timeout:
            server.close()
            return
        conn.settimeout(25)
        data = b""
        try:
            while b"\r\n\r\n" not in data and len(data) < 65536:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            received["raw"] = data
            try:
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                )
            except OSError:
                pass
            conn.close()
            server.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    assert ready.wait(5)
    port = int(received["port"])
    mitm = Mitm(tmp_path / "session")
    mitm.start()
    try:
        sock = socket.create_connection(("127.0.0.1", mitm.port), timeout=20)
        request = (
            f"GET http://127.0.0.1:{port}/oby-echo HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "X-Odd-Case: kept\r\n"
            "Cookie: a=1\r\n"
            "Cookie: b=2\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        sock.sendall(request.encode())
        while sock.recv(65536):
            pass
        sock.close()
    finally:
        mitm.stop()
    thread.join(timeout=5)

    raw = received.get("raw", b"")
    text = raw.decode("latin-1", errors="replace")
    assert "X-Odd-Case: kept\r\nCookie: a=1\r\nCookie: b=2\r\n" in text, text
    assert "proxy-authorization" not in text.lower()
