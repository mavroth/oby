"""Local mitmproxy that records the session and mirrors TLS with mitmcloak.

The browser talks only to this proxy. An upstream proxy, when set, is handed
to mitmcloak, which dials the origin with the browser's own TLS fingerprint.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from oby import record


def redact_proxy(url: str | None) -> str | None:
    """Drop userinfo so a saved session does not keep the proxy password."""
    if not url:
        return None
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit((parts.scheme, host, "", "", ""))


def mitmdump_argv() -> list[str]:
    # sys.prefix is this environment, even when sys.executable is a symlink
    # into Homebrew and that Homebrew bin has a different mitmdump.
    sibling = Path(sys.prefix) / "bin" / "mitmdump"
    if sibling.exists():
        return [str(sibling)]
    exe = shutil.which("mitmdump")
    if exe:
        return [exe]
    return [sys.executable, "-m", "mitmproxy.tools.main", "mitmdump"]


def cloak_addon_path() -> str:
    import mitmcloak.addon as addon

    return str(Path(addon.__file__).resolve())


def build_mitmdump_command(
    *,
    listen_port: int,
    confdir: Path,
    flow_path: Path,
    export_dir: Path,
    catalogue_dir: Path,
    upstream: str | None,
) -> list[str]:
    command = [
        *mitmdump_argv(),
        "--listen-host", "127.0.0.1",
        "--listen-port", str(listen_port),
        "-q",
        "--set", f"confdir={confdir}",
        "--set", "connection_strategy=lazy",
        "-s", cloak_addon_path(),
        "-s", str(Path(record.__file__).resolve()),
        "-w", str(flow_path),
        "--set", f"mitmcloak_export_dir={export_dir}",
        "--set", f"mitmcloak_catalogue_dir={catalogue_dir}",
        "--set", "mitmcloak_headers=exact",
        "--set", "mitmcloak_mode=auto",
    ]
    if upstream:
        command.extend(["--set", f"mitmcloak_proxy={upstream}"])
    return command


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _port_open(port: int) -> bool:
    with socket.socket() as sock:
        sock.settimeout(0.2)
        return sock.connect_ex(("127.0.0.1", port)) == 0


class Mitm:
    def __init__(self, out: Path, upstream: str | None = None, max_body: int = 1_000_000):
        self.out = out
        self.upstream = upstream
        self.max_body = max_body
        self.port = 0
        self.process: subprocess.Popen | None = None
        self.confdir = out / "mitm"
        self.flows = out / "flows.mitm"
        self.record_path = out / "flows.jsonl"
        self.log_path = out / "mitmdump.log"

    @property
    def server(self) -> str:
        # No userinfo. The recorder is open on loopback. Credentials here
        # would be a second proxy login, and the upstream proxy already
        # carries those on the mitmcloak side.
        return f"http://127.0.0.1:{self.port}"

    @property
    def ca_cert(self) -> Path:
        return self.confdir / "mitmproxy-ca-cert.pem"

    def start(self) -> str:
        self.out.mkdir(parents=True, exist_ok=True)
        self.confdir.mkdir(parents=True, exist_ok=True)
        (self.out / "presets").mkdir(exist_ok=True)
        (self.out / "seen").mkdir(exist_ok=True)
        self.port = free_port()
        command = build_mitmdump_command(
            listen_port=self.port,
            confdir=self.confdir,
            flow_path=self.flows,
            export_dir=self.out / "presets",
            catalogue_dir=self.out / "seen",
            upstream=self.upstream,
        )
        log = self.log_path.open("w", encoding="utf-8")
        env = os.environ.copy()
        env["OBY_RECORD"] = str(self.record_path)
        env["OBY_MAX_BODY"] = str(self.max_body)
        self.process = subprocess.Popen(
            command,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        self._wait_ready()
        return self.server

    def _wait_ready(self, timeout: float = 30) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.process and self.process.poll() is not None:
                raise RuntimeError(self._failure("mitmdump exited before it was ready"))
            if self.ca_cert.exists() and _port_open(self.port):
                return
            time.sleep(0.1)
        raise RuntimeError(self._failure("mitmdump did not open a port"))

    def _failure(self, prefix: str) -> str:
        tail = ""
        if self.log_path.exists():
            lines = self.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
            tail = "\n".join(lines[-40:])
        return f"{prefix}\n{tail}".rstrip()

    def stop(self) -> None:
        proc = self.process
        self.process = None
        if proc is None or proc.poll() is not None:
            return
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
