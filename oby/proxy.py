"""Local mitmproxy that records the session and mirrors TLS with mitmcloak.

The browser talks only to this proxy. An upstream proxy, when set, is handed
to mitmcloak, which dials the origin with the browser's own TLS fingerprint.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from oby.har import WS_NAME
from oby.scripts import PARSED_NAME


# The addons are named by path. Importing them here would load asyncio and
# mitmproxy into a process that only starts mitmdump.
_ADDONS = Path(__file__).resolve().parent
HISTORY_NAME = "history"
# One visit's files. The profile, the recorder's certificate, and the TLS
# presets belong to the browser and stay where they are.
_VISIT_FILES = (
    "flows.jsonl",
    WS_NAME,
    PARSED_NAME,
    "initiators.jsonl",
    "scripts.json",
    "scripts",
    "session.har",
    "storage.json",
    "meta.json",
    "flows.mitm",
)


def _has_exchange(path: Path) -> bool:
    try:
        with path.open(encoding="utf-8", errors="replace") as handle:
            return any(line.strip() for line in handle)
    except OSError:
        return False


def _visit_stamp(out: Path) -> str:
    """When the previous visit began, as a folder name."""
    started = None
    try:
        started = json.loads((out / "meta.json").read_text(encoding="utf-8")).get("started_at")
    except (OSError, ValueError, AttributeError):
        pass
    if not isinstance(started, str) or not started:
        try:
            moment = datetime.fromtimestamp((out / "flows.jsonl").stat().st_mtime, timezone.utc)
        except OSError:
            moment = datetime.now(timezone.utc)
        started = moment.isoformat()
    stamp = re.sub(r"[^0-9A-Za-z]+", "-", started.split(".")[0].replace("+00:00", "")).strip("-")
    return stamp or "visit"


def reset_capture(out: Path) -> Path | None:
    """Move the previous visit aside so this visit starts empty.

    The recorder appends. A reused folder otherwise still holds the last
    browser's startup traffic, and a reader can report that the new page
    never loaded. A previous visit that recorded an exchange is moved to
    history/<when it began>/ and nothing in it is deleted, so a launch that
    fails cannot cost a recording. A previous visit with no exchange is
    removed. Returns the history folder when one was written.
    """
    out.mkdir(parents=True, exist_ok=True)
    present = [name for name in _VISIT_FILES if (out / name).exists()]
    keep = _has_exchange(out / "flows.jsonl")
    target = None
    if keep:
        base = out / HISTORY_NAME / _visit_stamp(out)
        target = base
        number = 1
        while target.exists():
            number += 1
            target = base.with_name(f"{base.name}-{number}")
        target.mkdir(parents=True)
    for name in present:
        path = out / name
        try:
            if target is not None:
                path.rename(target / name)
            elif path.is_dir():
                shutil.rmtree(path, ignore_errors=True)
            else:
                path.unlink(missing_ok=True)
        except OSError:
            pass
    return target


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
        # The collector answers before mitmcloak. record.py stays last among
        # the scripts so its running() hook can place HTTP/2 capture after
        # mitmproxy's own next_layer addon.
        "-s", str(_ADDONS / "collect.py"),
        "-s", cloak_addon_path(),
        "-s", str(_ADDONS / "record.py"),
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
    def __init__(self, out: Path, upstream: str | None = None, max_body: int | None = None):
        self.out = out
        self.upstream = upstream
        self.max_body = max_body
        self.port = 0
        self.process: subprocess.Popen | None = None
        self.confdir = out / "mitm"
        self.flows = out / "flows.mitm"
        self.record_path = out / "flows.jsonl"
        self.ws_path = out / WS_NAME
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

    def prepare(self) -> str:
        """Clear the folder for this visit and choose the port, without starting.

        The agent server is started with this address while the recorder is
        still loading, so the two start side by side.
        """
        if not self.port:
            self.out.mkdir(parents=True, exist_ok=True)
            reset_capture(self.out)
            self.confdir.mkdir(parents=True, exist_ok=True)
            (self.out / "presets").mkdir(exist_ok=True)
            (self.out / "seen").mkdir(exist_ok=True)
            self.port = free_port()
        return self.server

    def start(self) -> str:
        self.prepare()
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
        env["OBY_WS"] = str(self.ws_path)
        # Bodies are kept whole unless a limit was asked for.
        env["OBY_MAX_BODY"] = str(self.max_body) if self.max_body else "0"
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
