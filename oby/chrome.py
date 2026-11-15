"""The browser: CloakBrowser, and a watcher on its DevTools protocol.

CloakBrowser is a patched Chromium with a build for each desktop platform,
so the browser runs on the machine itself. It is given the local recorder as
its proxy, and the recorder's certificate by its public key, which Chrome
accepts for every host including those on its HSTS list.

The watcher is a second DevTools client on a loopback port. It attaches to
every page, frame, and worker, and writes two logs:

scripts-parsed.jsonl  every script V8 parsed, with its source: fetched
                      files, inline scripts, eval, new Function, string
                      timers, blob workers.
initiators.jsonl      every request the browser made, with the script
                      frame that made it, and whether it was answered,
                      served from cache, or dropped.

Nothing is injected into the page. Only the Debugger and Network domains
are enabled. Runtime is left off, since a page can detect it. `debugger`
statements are skipped, so a page that uses them against DevTools is not
paused.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import socket
import struct
import threading
import time
import urllib.request
from pathlib import Path

from oby import initiators
from oby.scripts import PARSED_NAME

MAX_INFLIGHT = 16
DRAIN_SECONDS = 15.0
_WATCHED = frozenset({"page", "iframe", "worker", "shared_worker", "service_worker"})
_SKIP_URLS = ("chrome-extension://", "chrome://", "devtools://", "extensions::", "chrome-untrusted://")
# Playwright names what it evaluates in the page. Those are the driver's, not the site's.
_DRIVER_MARKS = ("__playwright", "__puppeteer", "pptr:")


# What Playwright itself evaluates in the page's own world.
_DRIVER_SOURCES = ("((utilityScript, ...args) =>", "(injected, ")
_ignored: set[str] = set()


def ignore_source(text: str) -> None:
    """Leave out a script the driver is about to run in the page, such as an agent's evaluate."""
    _ignored.add(text.strip())


def is_driver_source(text: str) -> bool:
    return text.startswith(_DRIVER_SOURCES) or text.strip() in _ignored or any(mark in text[-200:] for mark in _DRIVER_MARKS)


def spki_hash(ca_pem: Path) -> str:
    """The recorder CA's public key, as Chrome's SPKI list wants it."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    cert = x509.load_pem_x509_certificate(Path(ca_pem).read_bytes())
    der = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(hashlib.sha256(der).digest()).decode("ascii")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def launch_args(*, ca_pem: Path, debug_port: int) -> list[str]:
    return [
        # Chrome accepts a chain that holds this key, for any host. A plain
        # "ignore certificate errors" would accept anyone's certificate.
        f"--ignore-certificate-errors-spki-list={spki_hash(ca_pem)}",
        # Chrome skips the proxy for loopback unless told otherwise, and a
        # site on this machine would then go unrecorded.
        "--proxy-bypass-list=<-loopback>",
        f"--remote-debugging-port={debug_port}",
    ]


def launch_options(*, profile: Path, server: str, ca_pem: Path, debug_port: int, headless: bool, humanize: bool) -> dict:
    return {
        "user_data_dir": str(profile),
        "headless": headless,
        "proxy": server,
        "args": launch_args(ca_pem=ca_pem, debug_port=debug_port),
        "humanize": humanize,
    }


def launch(**options):
    """Open CloakBrowser on the recorder. Returns a Playwright browser context."""
    from cloakbrowser import launch_persistent_context

    return launch_persistent_context(**launch_options(**options))


async def launch_async(**options):
    from cloakbrowser import launch_persistent_context_async

    return await launch_persistent_context_async(**launch_options(**options))


# --------------------------------------------------------------- the socket


class _Socket:
    """A WebSocket client for the DevTools endpoint. Text frames only."""

    def __init__(self, url: str, timeout: float = 5.0):
        rest = url.split("://", 1)[1]
        address, _, path = rest.partition("/")
        host, _, port = address.partition(":")
        self._sock = socket.create_connection((host, int(port or 80)), timeout)
        key = base64.b64encode(secrets.token_bytes(16)).decode("ascii")
        # No Origin header. Chrome refuses a DevTools client that sends one.
        self._sock.sendall(
            (
                f"GET /{path} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\n"
                f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).encode("ascii")
        )
        head = b""
        while b"\r\n\r\n" not in head:
            chunk = self._sock.recv(4096)
            if not chunk:
                raise ConnectionError("the DevTools endpoint closed during the handshake")
            head += chunk
        if b" 101 " not in head.split(b"\r\n", 1)[0]:
            raise ConnectionError(head.split(b"\r\n", 1)[0].decode("latin-1"))
        self._rest = head.split(b"\r\n\r\n", 1)[1]
        self._sock.settimeout(None)
        self._lock = threading.Lock()

    def _read(self, count: int) -> bytes:
        while len(self._rest) < count:
            chunk = self._sock.recv(max(65536, count - len(self._rest)))
            if not chunk:
                raise ConnectionError("the DevTools endpoint closed")
            self._rest += chunk
        data, self._rest = self._rest[:count], self._rest[count:]
        return data

    def _frame(self, opcode: int, payload: bytes) -> None:
        mask = secrets.token_bytes(4)
        size = len(payload)
        if size < 126:
            head = struct.pack("!BB", 0x80 | opcode, 0x80 | size)
        elif size < 65536:
            head = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, size)
        else:
            head = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, size)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload)) if size < 4096 else _mask(payload, mask)
        with self._lock:
            self._sock.sendall(head + mask + masked)

    def send(self, text: str) -> None:
        self._frame(0x1, text.encode("utf-8"))

    def receive(self) -> str:
        """The next whole text message. Raises ConnectionError when the browser is gone."""
        parts: list[bytes] = []
        while True:
            first, second = self._read(2)
            opcode, size = first & 0x0F, second & 0x7F
            if size == 126:
                size = struct.unpack("!H", self._read(2))[0]
            elif size == 127:
                size = struct.unpack("!Q", self._read(8))[0]
            payload = self._read(size)
            if opcode == 0x8:
                raise ConnectionError("the DevTools endpoint closed")
            if opcode == 0x9:
                self._frame(0xA, payload)
                continue
            if opcode == 0xA:
                continue
            parts.append(payload)
            if first & 0x80:
                return b"".join(parts).decode("utf-8", errors="replace")

    def close(self) -> None:
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._sock.close()
        except OSError:
            pass


def _mask(payload: bytes, mask: bytes) -> bytes:
    repeated = (mask * (len(payload) // 4 + 1))[: len(payload)]
    return (int.from_bytes(payload, "big") ^ int.from_bytes(repeated, "big")).to_bytes(len(payload), "big")


# ------------------------------------------------------- what a packet means


def skip_url(url: str) -> bool:
    lowered = url.lower()
    return lowered.startswith(_SKIP_URLS) or any(mark in lowered for mark in _DRIVER_MARKS)


def script_kind(params: dict) -> str | None:
    """The scripts.json kind of one Debugger.scriptParsed, or None to leave it out.

    `eval` here also covers new Function and a string timer. V8 does not
    say which, so the source decides once it is read (see kind_from_source).
    """
    url = params.get("url") if isinstance(params.get("url"), str) else ""
    context = params.get("executionContextAuxData")
    if isinstance(context, dict) and context.get("type") == "isolated":
        # An isolated world is the driver's or an extension's, never the page's.
        return None
    if skip_url(url):
        return None
    if url.lower().startswith("blob:"):
        return "blob"
    if not url or params.get("hasSourceURL") or not url.lower().startswith(("http://", "https://", "file://")):
        return "eval"
    # A file starts at 0:0. An inline script starts where its tag ends.
    if params.get("startLine") or params.get("startColumn"):
        return "inline"
    return "network"


def kind_from_source(kind: str, source: str) -> str:
    if kind == "eval" and source.lstrip().startswith("(function anonymous("):
        return "function"
    return kind


def frame_of(initiator: dict) -> dict | None:
    """The script frame that made a request, in the form initiators.jsonl holds.

    Chrome counts lines and columns from 0. The log counts from 1, and the
    HAR writer turns it back for `_initiator`.
    """
    stack = initiator.get("stack")
    waited = None
    top = True
    while isinstance(stack, dict):
        if not top:
            # A parent stack is the code that was running before an await,
            # a timer, or a promise. Its description says which.
            waited = stack.get("description") or waited or "async"
        top = False
        frames = stack.get("callFrames")
        if isinstance(frames, list) and frames and isinstance(frames[0], dict):
            top = frames[0]
            if isinstance(top.get("url"), str) and top["url"]:
                shown = {
                    "url": top["url"],
                    "line": int(top.get("lineNumber") or 0) + 1,
                    "column": int(top.get("columnNumber") or 0) + 1,
                }
                if top.get("functionName"):
                    shown["function"] = top["functionName"]
                if waited:
                    shown["async"] = waited
                return shown
        stack = stack.get("parent")
    if isinstance(initiator.get("url"), str) and initiator.get("type") == "script":
        return {"url": initiator["url"], "line": int(initiator.get("lineNumber") or 0) + 1, "column": int(initiator.get("columnNumber") or 0) + 1}
    return None


def _wire_url(url: str) -> str:
    """The recorder writes a WebSocket handshake as the HTTP request it is."""
    if url.startswith("wss://"):
        return "https://" + url[6:]
    if url.startswith("ws://"):
        return "http://" + url[5:]
    return url


def request_rows(session: str, method: str, params: dict, hops: dict) -> list[dict]:
    """The lines to append to initiators.jsonl for one Network event."""
    request_id = params.get("requestId")
    if not isinstance(request_id, str):
        return []
    base = f"{session}:{request_id}"
    if method == "Network.requestWillBeSent":
        request = params.get("request") if isinstance(params.get("request"), dict) else {}
        url = request.get("url")
        if not isinstance(url, str) or not url.lower().startswith(("http://", "https://")):
            return []
        rows: list[dict] = []
        redirect = params.get("redirectResponse")
        if isinstance(redirect, dict):
            # The hop before this one was answered with a redirect.
            rows.append({"rid": f"{base}#{hops.get(base, 0)}", "update": {"status": str(redirect.get("status") or "")}})
            hops[base] = hops.get(base, 0) + 1
        rid = f"{base}#{hops.setdefault(base, 0)}"
        row = {"rid": rid, "url": url.split("#", 1)[0], "method": str(request.get("method") or "GET"), "type": str(params.get("type") or "other").lower()}
        if isinstance(params.get("wallTime"), (int, float)):
            row["time"] = params["wallTime"]
        if isinstance(params.get("documentURL"), str):
            row["document"] = params["documentURL"]
        rows.append(row)
        initiator = params.get("initiator") if isinstance(params.get("initiator"), dict) else {}
        frame = frame_of(initiator)
        if frame:
            rows.append({"rid": rid, "frame": frame})
        return rows
    rid = f"{base}#{hops.get(base, 0)}"
    if method == "Network.webSocketCreated":
        url = params.get("url")
        if not isinstance(url, str):
            return []
        rows = [{"rid": rid, "url": _wire_url(url), "method": "GET", "type": "websocket"}]
        frame = frame_of(params.get("initiator") if isinstance(params.get("initiator"), dict) else {})
        if frame:
            rows.append({"rid": rid, "frame": frame})
        return rows
    if method == "Network.webSocketHandshakeResponseReceived":
        response = params.get("response") if isinstance(params.get("response"), dict) else {}
        return [{"rid": rid, "update": {"status": str(response.get("status") or "")}}]
    if method == "Network.responseReceived":
        response = params.get("response") if isinstance(params.get("response"), dict) else {}
        update: dict = {"status": str(response.get("status") or "")}
        # A copy still in memory, or one shared with a request in flight, is
        # not flagged as cached. It is the one answer that used no connection.
        if response.get("fromDiskCache") or response.get("fromPrefetchCache") or response.get("connectionId") == 0:
            update["cached"] = True
        if response.get("fromServiceWorker"):
            update["service_worker"] = True
        return [{"rid": rid, "update": update}]
    if method == "Network.requestServedFromCache":
        return [{"rid": rid, "update": {"cached": True}}]
    if method == "Network.loadingFailed":
        reason = params.get("blockedReason") or params.get("errorText")
        return [{"rid": rid, "update": {"blocked": str(reason)}}] if reason else []
    return []


# ---------------------------------------------------------------- the watch


class Watch:
    def __init__(self, port: int, out: Path):
        self.port = port
        self.out = Path(out)
        self.dest = self.out / PARSED_NAME
        self._socket: _Socket | None = None
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._next = 0
        self._calls: dict[int, object] = {}
        self._queue: list[dict] = []
        self._inflight: dict[int, dict] = {}
        self._hops: dict[str, int] = {}
        self._sessions: set[str] = set()
        self._idle = threading.Event()
        self._idle.set()
        self.attached = False

    # ---- connection

    def start(self, timeout: float = 15.0) -> bool:
        """Connect to the browser. False if its DevTools port never answered."""
        deadline = time.monotonic() + timeout
        url = None
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=2) as reply:
                    url = json.loads(reply.read())["webSocketDebuggerUrl"]
                break
            except Exception:
                time.sleep(0.2)
        if not url:
            return False
        try:
            self._socket = _Socket(url)
        except (OSError, ConnectionError):
            return False
        self._thread = threading.Thread(target=self._run, name="oby-chrome-watch", daemon=True)
        self._thread.start()
        self._send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True})
        self.attached = True
        return True

    def stop(self, drain: float = DRAIN_SECONDS) -> None:
        """Wait for the script texts still owed, then close."""
        if self._socket is not None and self._thread is not None and self._thread.is_alive():
            self._idle.wait(drain)
        sock, self._socket = self._socket, None
        if sock is not None:
            sock.close()
        if self._thread is not None:
            self._thread.join(timeout=3)
        self._flush_unfetched()

    def _send(self, method: str, params: dict | None = None, session: str | None = None, then=None) -> int | None:
        sock = self._socket
        if sock is None:
            return None
        with self._lock:
            self._next += 1
            number = self._next
            if then is not None:
                self._calls[number] = then
        message: dict = {"id": number, "method": method}
        if params:
            message["params"] = params
        if session:
            message["sessionId"] = session
        try:
            sock.send(json.dumps(message))
        except OSError:
            return None
        return number

    def _run(self) -> None:
        sock = self._socket
        while sock is not None:
            try:
                message = json.loads(sock.receive())
            except (ConnectionError, OSError):
                break
            except ValueError:
                continue
            try:
                self._handle(message)
            except Exception:
                # One odd packet must not end the watch.
                continue
        self._idle.set()

    # ---- packets

    def _handle(self, message: dict) -> None:
        if "id" in message:
            then = self._calls.pop(message["id"], None)
            if then is not None:
                then(message)
            return
        method = message.get("method")
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        session = message.get("sessionId") or ""
        if method == "Target.attachedToTarget":
            info = params.get("targetInfo") if isinstance(params.get("targetInfo"), dict) else {}
            child = params.get("sessionId")
            if isinstance(child, str) and info.get("type") in _WATCHED and not skip_url(str(info.get("url") or "")):
                self._arm(child)
        elif method == "Target.detachedFromTarget":
            self._sessions.discard(str(params.get("sessionId") or ""))
        elif method == "Debugger.scriptParsed":
            self._note(session, params)
        elif method == "Debugger.paused":
            self._send("Debugger.resume", session=session)
        elif isinstance(method, str) and method.startswith("Network."):
            rows = request_rows(session, method, params, self._hops)
            if rows:
                self._append(self.out / initiators.INITIATORS_NAME, rows)

    def _arm(self, session: str) -> None:
        if session in self._sessions:
            return
        self._sessions.add(session)
        # Frames in another process and workers are targets of this one.
        self._send("Target.setAutoAttach", {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True}, session)
        self._send("Network.enable", session=session)
        # Enabling replays every script this target already parsed.
        self._send("Debugger.enable", session=session)
        self._send("Debugger.setSkipAllPauses", {"skip": True}, session)

    def _note(self, session: str, params: dict) -> None:
        kind = script_kind(params)
        script = params.get("scriptId")
        if kind is None or not isinstance(script, str):
            return
        url = params.get("url") if isinstance(params.get("url"), str) else ""
        form = {"session": session, "script": script, "kind": kind, "url": url[:2048]}
        with self._lock:
            # A text that exists only in the engine goes ahead of a file,
            # which can be read back from the recording if the page leaves.
            if kind in ("network", "inline"):
                self._queue.append(form)
            else:
                index = next((i for i, item in enumerate(self._queue) if item["kind"] in ("network", "inline")), len(self._queue))
                self._queue.insert(index, form)
            self._idle.clear()
        self._pump()

    def _pump(self) -> None:
        while True:
            with self._lock:
                if not self._queue or len(self._inflight) >= MAX_INFLIGHT:
                    return
                form = self._queue.pop(0)
            number = self._send(
                "Debugger.getScriptSource",
                {"scriptId": form["script"]},
                form["session"],
                then=lambda reply, form=form: self._source(form, reply),
            )
            if number is None:
                self._owe(form)
                return
            with self._lock:
                self._inflight[number] = form

    def _source(self, form: dict, reply: dict) -> None:
        with self._lock:
            self._inflight.pop(reply.get("id"), None)
        result = reply.get("result") if isinstance(reply.get("result"), dict) else {}
        text = result.get("scriptSource")
        if isinstance(text, str) and text:
            if not is_driver_source(text):
                row = {"kind": kind_from_source(form["kind"], text), "url": form["url"], "source": text, "introduction": ""}
                self._append(self.dest, [row])
        elif "error" in reply:
            self._owe(form)
        self._pump()
        with self._lock:
            if not self._queue and not self._inflight:
                self._idle.set()

    def _owe(self, form: dict) -> None:
        """Record that a script was parsed when its text never came."""
        self._append(self.dest, [{"kind": form["kind"], "url": form["url"], "introduction": "", "unfetched": True}])

    def _flush_unfetched(self) -> None:
        with self._lock:
            waiting = list(self._inflight.values()) + self._queue
            self._inflight.clear()
            self._queue = []
        for form in waiting:
            self._owe(form)

    def _append(self, path: Path, rows: list[dict]) -> None:
        text = "".join(json.dumps(row, ensure_ascii=False) + "\n" for row in rows)
        with self._write_lock:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(text)
            except OSError:
                pass


_watch: Watch | None = None


def start_watch(port: int, out: Path) -> bool:
    """Start the one watch of this process. False if the DevTools port never answered."""
    global _watch
    watch = Watch(port, out)
    if not watch.start():
        return False
    _watch = watch
    return True


def stop_watch() -> None:
    global _watch
    watch, _watch = _watch, None
    if watch is not None:
        watch.stop()
