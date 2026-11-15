from __future__ import annotations

import base64
import hashlib
import json
import socket
import struct
import threading
from pathlib import Path

from oby import chrome


def test_a_parsed_script_is_named_by_where_it_came_from():
    assert chrome.script_kind({"url": "https://a.example/app.js", "startLine": 0, "startColumn": 0}) == "network"
    assert chrome.script_kind({"url": "https://a.example/", "startLine": 3, "startColumn": 8}) == "inline"
    assert chrome.script_kind({"url": ""}) == "eval"
    assert chrome.script_kind({"url": "named-by-the-page.js", "hasSourceURL": True}) == "eval"
    assert chrome.script_kind({"url": "blob:https://a.example/1-2"}) == "blob"
    # The driver's world, an extension, and what Playwright evaluates are not the page's.
    assert chrome.script_kind({"url": "", "executionContextAuxData": {"type": "isolated"}}) is None
    assert chrome.script_kind({"url": "chrome-extension://abc/content.js"}) is None
    assert chrome.script_kind({"url": "__playwright_evaluation_script__1", "hasSourceURL": True}) is None

    assert chrome.kind_from_source("eval", "(function anonymous(a\n) {\nreturn a\n})") == "function"
    assert chrome.kind_from_source("eval", "fetch('/x')") == "eval"
    assert chrome.kind_from_source("network", "(function anonymous(") == "network"
    assert chrome.is_driver_source("((utilityScript, ...args) => utilityScript.evaluate(...args))")
    assert not chrome.is_driver_source("fetch('/x')")
    chrome.ignore_source(" document.title ")
    assert chrome.is_driver_source("document.title")


def test_the_frame_that_made_a_request_counts_from_one_and_follows_an_await():
    direct = {"type": "script", "stack": {"callFrames": [{"functionName": "load", "url": "https://a.example/app.js", "lineNumber": 0, "columnNumber": 20}]}}
    assert chrome.frame_of(direct) == {"url": "https://a.example/app.js", "line": 1, "column": 21, "function": "load"}
    waited = {
        "type": "script",
        "stack": {"callFrames": [], "parent": {"description": "await", "callFrames": [{"functionName": "", "url": "https://a.example/app.js", "lineNumber": 4, "columnNumber": 2}]}},
    }
    assert chrome.frame_of(waited) == {"url": "https://a.example/app.js", "line": 5, "column": 3, "async": "await"}
    assert chrome.frame_of({"type": "parser", "url": "https://a.example/"}) is None


def test_network_events_become_the_request_list_the_coverage_check_reads(tmp_path: Path):
    from oby import initiators

    hops: dict = {}
    rows: list[dict] = []

    def event(method, **params):
        rows.extend(chrome.request_rows("S", method, params, hops))

    event("Network.requestWillBeSent", requestId="1", type="Document", wallTime=10.0, documentURL="https://a.example/",
          request={"url": "http://a.example/#top", "method": "GET"}, initiator={"type": "other"})
    # The same id again is the next hop of a redirect.
    event("Network.requestWillBeSent", requestId="1", type="Document", request={"url": "https://a.example/", "method": "GET"},
          redirectResponse={"status": 301}, initiator={"type": "other"})
    event("Network.responseReceived", requestId="1", response={"status": 200, "connectionId": 7})
    event("Network.requestWillBeSent", requestId="2", type="Script", request={"url": "https://a.example/app.js", "method": "GET"},
          initiator={"type": "parser"})
    # Shared with a request in flight: no cache flag, and no connection.
    event("Network.responseReceived", requestId="2", response={"status": 200, "connectionId": 0})
    event("Network.requestWillBeSent", requestId="3", type="Fetch", request={"url": "data:text/plain,x", "method": "GET"}, initiator={})
    event("Network.webSocketCreated", requestId="4", url="wss://a.example/live")
    event("Network.requestWillBeSent", requestId="5", type="Fetch", request={"url": "https://a.example/gone", "method": "POST"}, initiator={})
    event("Network.loadingFailed", requestId="5", errorText="net::ERR_ABORTED")

    path = tmp_path / initiators.INITIATORS_NAME
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    requests = initiators.read(path)
    assert [(item["method"], item["url"], item.get("status"), item.get("cached")) for item in requests] == [
        ("GET", "http://a.example/", "301", None),
        ("GET", "https://a.example/", "200", None),
        ("GET", "https://a.example/app.js", "200", True),
        ("GET", "https://a.example/live", None, None),
        ("POST", "https://a.example/gone", None, None),
    ]
    flows = [{"method": "GET", "url": "http://a.example/"}, {"method": "GET", "url": "https://a.example/"}, {"method": "GET", "url": "https://a.example/live"}]
    (tmp_path / "flows.jsonl").write_text("", encoding="utf-8")
    covered = initiators.coverage(tmp_path, flows)
    assert covered["missing"] == [] and covered["from_cache"] == 1
    assert [item["url"] for item in covered["unanswered"]] == ["https://a.example/gone"]


def test_chrome_is_given_the_recorder_ca_by_its_public_key(tmp_path: Path):
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "recorder")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = tmp_path / "ca.pem"
    pem.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    expected = base64.b64encode(hashlib.sha256(spki).digest()).decode()

    args = chrome.launch_args(ca_pem=pem, debug_port=9333)
    assert f"--ignore-certificate-errors-spki-list={expected}" in args
    assert "--remote-debugging-port=9333" in args
    # A site on this machine goes through the recorder too.
    assert "--proxy-bypass-list=<-loopback>" in args
    assert not any(arg == "--ignore-certificate-errors" for arg in args)


class _FakeChrome:
    """Enough of a DevTools endpoint to attach one page and hand over two scripts."""

    def __init__(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]
        self.sent: list[dict] = []
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        head = b""
        while b"\r\n\r\n" not in head:
            head += conn.recv(4096)
        if head.startswith(b"GET /json/version"):
            body = json.dumps({"webSocketDebuggerUrl": f"ws://127.0.0.1:{self.port}/devtools/browser/x"}).encode()
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            conn.close()
            return
        assert b"Origin:" not in head
        conn.sendall(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
        buffer = head.split(b"\r\n\r\n", 1)[1]
        while True:
            while len(buffer) < 2 or len(buffer) < self._need(buffer):
                chunk = conn.recv(65536)
                if not chunk:
                    return
                buffer += chunk
            size = self._need(buffer)
            frame, buffer = buffer[:size], buffer[size:]
            length = frame[1] & 0x7F
            offset = 2 + (2 if length == 126 else 8 if length == 127 else 0)
            mask, payload = frame[offset:offset + 4], frame[offset + 4:]
            message = json.loads(bytes(byte ^ mask[i % 4] for i, byte in enumerate(payload)))
            self.sent.append(message)
            for reply in self._answer(message):
                data = json.dumps(reply).encode()
                head = struct.pack("!BB", 0x81, len(data)) if len(data) < 126 else struct.pack("!BBH", 0x81, 126, len(data))
                conn.sendall(head + data)

    @staticmethod
    def _need(buffer: bytes) -> int:
        length = buffer[1] & 0x7F
        if length == 126:
            return 8 + struct.unpack("!H", buffer[2:4])[0] if len(buffer) >= 4 else 1 << 30
        return 6 + length

    def _answer(self, message: dict) -> list[dict]:
        method, session = message["method"], message.get("sessionId")
        replies = [{"id": message["id"], "result": {}}]
        if method == "Target.setAutoAttach" and session is None:
            replies.append({"method": "Target.attachedToTarget", "params": {"sessionId": "P", "targetInfo": {"type": "page", "url": "https://a.example/"}}})
        if method == "Debugger.enable":
            for number, url in (("1", "https://a.example/app.js"), ("2", "")):
                replies.append({"method": "Debugger.scriptParsed", "sessionId": session, "params": {"scriptId": number, "url": url}})
            replies.append({"method": "Network.requestWillBeSent", "sessionId": session, "params": {
                "requestId": "9", "type": "Fetch", "request": {"url": "https://a.example/api", "method": "POST"},
                "initiator": {"type": "script", "stack": {"callFrames": [{"functionName": "go", "url": "https://a.example/app.js", "lineNumber": 0, "columnNumber": 4}]}}}})
        if method == "Debugger.getScriptSource":
            source = {"1": "APP()", "2": "fetch('/from-eval')"}[message["params"]["scriptId"]]
            replies[0] = {"id": message["id"], "result": {"scriptSource": source}}
        return replies


def test_the_watch_attaches_to_a_page_and_writes_scripts_and_requests(tmp_path: Path):
    fake = _FakeChrome()
    watch = chrome.Watch(fake.port, tmp_path)
    try:
        assert watch.start(timeout=5)
        deadline = threading.Event()
        for _ in range(100):
            if (tmp_path / "scripts-parsed.jsonl").exists() and len((tmp_path / "scripts-parsed.jsonl").read_text().splitlines()) == 2:
                break
            deadline.wait(0.05)
    finally:
        watch.stop(drain=2)
        fake.server.close()

    methods = [(message["method"], message.get("sessionId")) for message in fake.sent]
    assert ("Debugger.enable", "P") in methods and ("Network.enable", "P") in methods
    assert ("Debugger.setSkipAllPauses", "P") in methods
    # Runtime is what a page can detect. It is never turned on.
    assert not any(method.startswith("Runtime.") for method, _session in methods)

    scripts = [json.loads(line) for line in (tmp_path / "scripts-parsed.jsonl").read_text(encoding="utf-8").splitlines()]
    assert sorted((row["kind"], row["url"], row["source"]) for row in scripts) == [
        ("eval", "", "fetch('/from-eval')"),
        ("network", "https://a.example/app.js", "APP()"),
    ]
    requests = [json.loads(line) for line in (tmp_path / "initiators.jsonl").read_text(encoding="utf-8").splitlines()]
    assert requests[0]["url"] == "https://a.example/api" and requests[0]["method"] == "POST"
    assert requests[1]["frame"] == {"url": "https://a.example/app.js", "line": 1, "column": 5, "function": "go"}


def test_a_text_that_exists_only_in_the_engine_goes_ahead_of_files_in_the_backlog(tmp_path: Path):
    watch = chrome.Watch(0, tmp_path)
    # No socket: nothing is sent, so the backlog shows the order.
    watch._pump = lambda: None
    for number, url in enumerate(["https://a.example/1.js", "https://a.example/2.js", "", "blob:https://a.example/b"]):
        watch._note("P", {"scriptId": str(number), "url": url})
    assert [form["kind"] for form in watch._queue] == ["eval", "blob", "network", "network"]
    watch._flush_unfetched()
    owed = [json.loads(line) for line in (tmp_path / "scripts-parsed.jsonl").read_text(encoding="utf-8").splitlines()]
    assert all(row["unfetched"] for row in owed) and len(owed) == 4
