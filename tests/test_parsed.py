"""The Firefox parsed-script listener, without launching Firefox."""

import json
from pathlib import Path

from oby.parsed import (
    DEBUGGER_PREFS,
    PacketStream,
    arm_launch,
    kind_for,
    skip_url,
)
from oby.scripts import write_scripts


class FakeSocket:
    def __init__(self, data: bytes):
        self.data = data

    def settimeout(self, _timeout) -> None:
        return None

    def recv(self, count: int) -> bytes:
        if not self.data:
            return b""
        chunk = self.data[:count]
        self.data = self.data[count:]
        return chunk


def _packets(*objects) -> bytes:
    raw = b""
    for obj in objects:
        body = json.dumps(obj, separators=(",", ":")).encode()
        raw += f"{len(body)}:".encode("ascii") + body
    return raw


def _read_all(data: bytes) -> list:
    stream = PacketStream(FakeSocket(data), __import__("threading").Event())
    found = []
    while True:
        try:
            found.append(stream.read_packet(1))
        except (EOFError, TimeoutError):
            return found


def test_packets_survive_a_short_read():
    payload = _packets({"from": "root", "applicationType": "browser"}, {"type": "newSource"})
    sock = FakeSocket(payload)
    original = sock.recv

    def one_byte(count: int) -> bytes:
        return original(1)

    sock.recv = one_byte
    stream = PacketStream(sock, __import__("threading").Event())
    first = stream.read_packet(2)
    second = stream.read_packet(2)
    assert first["applicationType"] == "browser"
    assert second["type"] == "newSource"


def test_bulk_packet_keeps_its_body():
    data = b"bulk actor1 substring 5:hello"
    pkt = _read_all(data)[0]
    assert pkt["actor"] == "actor1"
    assert pkt["bulk_type"] == "substring"
    assert pkt["data"] == b"hello"


def test_kind_follows_the_introduction_type():
    assert kind_for("https://cdn.example/react-vendors.js", "") == "network"
    assert kind_for("https://example.com/page", "scriptElement") == "inline"
    assert kind_for("https://example.com/page", "eval") == "eval"
    assert kind_for("https://example.com/page", "Function") == "function"
    assert kind_for("https://example.com/page", "AsyncFunction") == "function"
    assert kind_for("https://example.com/page", "domTimer") == "timer"
    assert kind_for("blob:https://example.com/uuid", "") == "blob"
    assert kind_for("data:text/javascript,var%20n", "scriptElement") == "network"
    assert kind_for("javascript:void 0", "javascriptURL") == "eval"
    assert kind_for("https://example.com/app.wasm", "wasm") is None
    assert kind_for("", "debugger eval") is None


def test_browser_chrome_is_not_a_page_script():
    assert skip_url("chrome://browser/content/browser.xhtml")
    assert skip_url("resource://app/main.js")
    assert skip_url("moz-extension://abc/content.js")
    assert skip_url("about:newtab")
    assert not skip_url("about:blank")
    assert not skip_url("https://example.com/app.js")
    assert not skip_url("")


def test_launch_asks_firefox_to_report_parsed_scripts():
    class Launch:
        _extra_args = ["--width", "10"]
        _extra_prefs = None

    launch = Launch()
    arm_launch(launch)
    assert launch._extra_args[:2] == ["--width", "10"]
    assert launch._extra_args[2] == "--start-debugger-server"
    port = int(launch._extra_args[3])
    assert launch._oby_debugger_port == port
    assert launch._extra_prefs["zoom.stealth.debugger.force_detach"] is False
    assert launch._extra_prefs["devtools.debugger.remote-enabled"] is True
    assert set(DEBUGGER_PREFS) <= set(launch._extra_prefs)
    arm_launch(launch)
    assert launch._extra_args.count("--start-debugger-server") == 1
    assert launch._oby_debugger_port == port


def test_parsed_scripts_replace_the_wire_copy_and_stay_whole(tmp_path: Path):
    flows = tmp_path / "flows.jsonl"
    flows.write_text(
        json.dumps(
            {
                "url": "https://example.com/",
                "response_headers": [["content-type", "text/html"]],
                "response_body": {"text": "<script>WIRE</script>", "encoding": "utf-8"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    source = "vendor-marker" + ("x" * 600_000) + "vendor-end-marker"
    parsed = tmp_path / "scripts-parsed.jsonl"
    parsed.write_text(
        json.dumps(
            {
                "kind": "network",
                "url": "https://cdn.example/react-vendors.js",
                "source": source,
                "introduction": "",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    dest = tmp_path / "scripts.json"
    assert write_scripts(flows, tmp_path / "scripts-live.jsonl", dest, parsed) == 1
    body = json.loads(dest.read_text(encoding="utf-8"))
    item = body["scripts"][0]
    assert item["length"] == len(source)
    assert item["source"].endswith("vendor-end-marker")
    assert "truncated" not in item
    assert "WIRE" not in dest.read_text(encoding="utf-8")
    assert "zoom.stealth.debugger.force_detach" in body["note"]


def test_an_http_page_thread_is_paused_so_workers_can_be_armed(tmp_path):
    from oby.parsed import Listener

    listener = Listener(0, tmp_path / "scripts-parsed.jsonl")

    class Sock:
        def sendall(self, _data: bytes) -> None:
            return

    listener._sock = Sock()
    listener._observe(
        {
            "type": "target-available-form",
            "target": {
                "actor": "win",
                "targetType": "frame",
                "threadActor": "thr",
                "url": "https://example.test/",
            },
        }
    )
    listener._observe(
        {
            "type": "target-available-form",
            "target": {
                "actor": "blank",
                "targetType": "frame",
                "threadActor": "blank-thread",
                "url": "about:blank",
            },
        }
    )
    assert listener._pause_threads == {"thr"}


def test_the_document_route_is_removed_before_its_body_runs(monkeypatch):
    from oby import parsed
    from oby.parsed import _hold_documents

    events = []

    def note_wait(timeout=8):
        events.append(("wait", timeout))
        return True

    monkeypatch.setattr(parsed, "wait_for_document_thread", note_wait)

    class Request:
        resource_type = "document"

        def is_navigation_request(self):
            return True

    class Route:
        request = Request()

        def continue_(self):
            events.append("continue")

    class Context:
        def route(self, pattern, handler):
            events.append(("route", pattern, isinstance(pattern, str)))
            self.handler = handler

        def unroute(self, pattern, _handler):
            events.append(("unroute", pattern))

    class Page:
        def __init__(self):
            self.context = Context()

        def goto(self, url):
            return url

    page = Page()
    _hold_documents(page, "http://127.0.0.1:9/?q=1#section")
    page.context.handler(Route())
    assert events[0][0] == "route"
    assert events[0][2] is True
    assert "\\?" in events[0][1]
    assert [step[0] if isinstance(step, tuple) else step for step in events[1:]] == [
        "wait",
        "unroute",
        "continue",
    ]
    assert events[1][1] == 8


def test_a_connected_worker_waits_until_its_script_can_load(tmp_path):
    from oby.parsed import Listener

    listener = Listener(0, tmp_path / "scripts-parsed.jsonl")
    thread = "server1.conn0.watcher3.process6//workerTarget24/thread1"
    listener._observe({"type": "connected", "threadActor": thread})
    assert thread in listener._later_ids
    assert listener._new_threads == []


def test_a_worker_attaches_after_its_script_can_load_and_a_destroyed_one_does_not(tmp_path):
    from oby.parsed import Listener

    listener = Listener(0, tmp_path / "scripts-parsed.jsonl")
    worker = "server1.conn0.watcher3.process6//workerTarget24/thread1"
    listener._observe(
        {
            "type": "target-available-form",
            "target": {
                "actor": "w",
                "threadActor": worker,
                "targetType": "worker",
                "url": "http://127.0.0.1/worker.js",
            },
        }
    )
    assert worker not in listener._new_threads
    assert worker in listener._later_ids
    listener._observe(
        {
            "type": "target-destroyed-form",
            "target": {
                "threadActor": "server1.conn0.watcher3.process0//workerTarget4/thread1",
                "url": "resource://app/worker.js",
                "type": 0,
            },
        }
    )
    assert listener._new_threads == []
    listener._later[:] = [(0.0, worker)]
    listener._promote_workers()
    assert listener._new_threads == [worker]


def test_worker_watch_is_one_request_and_not_repeated_for_a_page(tmp_path):
    from oby.parsed import Listener

    class Sock:
        def __init__(self):
            self.sent: list[bytes] = []

        def sendall(self, data: bytes) -> None:
            self.sent.append(data)

    listener = Listener(0, tmp_path / "scripts-parsed.jsonl")
    sock = Sock()
    listener._sock = sock
    listener._watcher = "watcher1"
    listener._watch_workers()
    listener._watch_workers()
    page = {"actor": "win2", "targetType": "frame", "threadActor": "t2", "url": "http://127.0.0.1/"}
    listener._observe({"type": "target-available-form", "target": page})
    listener._observe({"workers": [{"actor": "d1", "url": "blob:n"}], "from": "win2"})
    watches = [item for item in sock.sent if b'"targetType":"worker"' in item]
    assert len(watches) == 1
    assert b'"to":"watcher1"' in watches[0]


def test_worker_attach_patch_is_the_same_size_and_idempotent(tmp_path):
    from oby.enginefix import (
        CONTEXT_NEW,
        CONTEXT_OLD,
        FILTER_NEW,
        FILTER_OLD,
        NEW,
        OLD,
        READY_NEW,
        READY_OLD,
        RELEASE_NEW,
        RELEASE_OLD,
        patch_browser_jar,
    )

    assert len(OLD) == len(NEW)
    assert len(FILTER_OLD) == len(FILTER_NEW)
    assert len(CONTEXT_OLD) == len(CONTEXT_NEW)
    assert len(RELEASE_OLD) == len(RELEASE_NEW)
    assert len(READY_OLD) == len(READY_NEW)
    jar = tmp_path / "omni.ja"
    original = (
        b"before\n"
        + OLD
        + b"\n"
        + FILTER_OLD
        + b"\n"
        + CONTEXT_OLD
        + b"\n"
        + RELEASE_OLD
        + READY_OLD
        + b"after"
    )
    jar.write_bytes(original)
    assert patch_browser_jar(jar) == "patched"
    assert jar.read_bytes() == (
        b"before\n"
        + NEW
        + b"\n"
        + FILTER_NEW
        + b"\n"
        + CONTEXT_NEW
        + b"\n"
        + RELEASE_NEW
        + READY_NEW
        + b"after"
    )
    assert patch_browser_jar(jar) == "ready"


def test_window_target_lists_workers_and_a_worker_target_does_not():
    from oby.parsed import is_window_target

    assert is_window_target({"targetType": "frame", "actor": "tab", "innerWindowId": 1})
    assert is_window_target({"actor": "tab", "browsingContextID": 4, "threadActor": "thr"})
    assert not is_window_target({"targetType": "worker", "actor": "worker"})
    assert not is_window_target({"targetType": "process", "actor": "process"})
    assert not is_window_target({"actor": "bare"})


def test_page_navigation_is_held_on_the_page_itself():
    from oby.parsed import arm_navigation

    calls = []

    class Page:
        def goto(self, url):
            calls.append(url)
            return url

    page = Page()
    arm_navigation(page)
    assert page.goto._oby_nav is True
    assert page.goto("https://example.test/") == "https://example.test/"
    assert calls == ["https://example.test/"]


def test_attached_debugger_skips_the_page_hook(monkeypatch):
    monkeypatch.setattr("oby.parsed.start_parsed", lambda _launcher: True)
    seen = []

    class Ctx:
        def add_init_script(self, script):
            seen.append(script)
            return "handle"

    class Browser:
        def __enter__(self):
            return Ctx()

    from oby.scripts import _wrap_enter

    _wrap_enter(Browser, "__enter__", awaitable=False)
    Browser().__enter__()
    assert seen == []
