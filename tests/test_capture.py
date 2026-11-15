"""Whole bodies, WebSocket messages, event streams, timings, pages, and history."""

import json
from pathlib import Path
from types import SimpleNamespace

from oby.har import HAR_NAME, WS_NAME, assign_pages, document, events, write_har
from oby.record import body_field, close_row, message_row, timing_of


def _row(url, *, status=200, navigate=False, ident="", headers=None, body=None, ctype="text/html"):
    request_headers = [["sec-fetch-dest", "document"], ["sec-fetch-mode", "navigate"]] if navigate else []
    return {
        "id": ident,
        "url": url,
        "method": "GET",
        "status": status,
        "request_headers": request_headers + (headers or []),
        "response_headers": [["content-type", ctype]],
        "response_body": {"text": body, "encoding": "utf-8", "bytes": len(body or "")},
    }


def test_a_body_is_kept_whole_unless_a_limit_is_set(monkeypatch):
    monkeypatch.delenv("OBY_MAX_BODY", raising=False)
    big = b"a" * 3_000_000
    field = body_field(big)
    assert field["truncated"] is False
    assert len(field["text"]) == 3_000_000
    monkeypatch.setenv("OBY_MAX_BODY", "0")
    assert body_field(big)["truncated"] is False
    monkeypatch.setenv("OBY_MAX_BODY", "10")
    cut = body_field(big)
    assert cut["truncated"] is True and len(cut["text"]) == 10 and cut["bytes"] == 3_000_000


def test_timing_reads_every_clock():
    flow = SimpleNamespace(
        request=SimpleNamespace(timestamp_start=10.0, timestamp_end=10.1),
        response=SimpleNamespace(timestamp_start=10.6, timestamp_end=10.9),
        client_conn=SimpleNamespace(timestamp_start=9.0, timestamp_tls_setup=9.2),
        server_conn=SimpleNamespace(timestamp_start=10.15, timestamp_tcp_setup=10.2, timestamp_tls_setup=10.3),
    )
    timing = timing_of(flow)
    assert timing["request_start"] == 10.0 and timing["response_end"] == 10.9
    assert timing["client"] == {"start": 9.0, "tls": 9.2}
    assert timing["server"] == {"start": 10.15, "tcp": 10.2, "tls": 10.3}

    entry = document([{"url": "https://a.example/", "timing": timing}])["log"]["entries"][0]
    timings = entry["timings"]
    assert round(timings["send"]) == 100
    assert round(timings["connect"]) == 150 and round(timings["ssl"]) == 100
    assert round(timings["wait"]) == 350
    assert round(timings["receive"]) == 300
    assert round(entry["time"]) == 900
    assert entry["_oby"]["timing"]["client"]["tls"] == 9.2


def test_timing_without_a_server_connection_leaves_connect_unknown():
    timing = {"request_start": 1.0, "request_end": 1.0, "response_start": 1.5, "response_end": 1.5}
    timings = document([{"url": "https://a.example/", "timing": timing}])["log"]["entries"][0]["timings"]
    assert timings["connect"] == -1 and timings["ssl"] == -1
    assert round(timings["wait"]) == 500


def test_websocket_messages_ride_on_their_handshake(tmp_path: Path):
    flow = SimpleNamespace(
        id="ws-1",
        request=SimpleNamespace(pretty_url="https://a.example/socket"),
        websocket=SimpleNamespace(close_code=1000, close_reason="bye", closed_by_client=True, timestamp_end=5.0),
    )
    sent = SimpleNamespace(content=b"hello", is_text=True, from_client=True, timestamp=1.0, dropped=False)
    got = SimpleNamespace(content=b"\x00\xff", is_text=False, from_client=False, timestamp=2.0, dropped=False)
    rows = [message_row(flow, sent), message_row(flow, got), close_row(flow)]
    assert rows[0]["text"] == "hello" and rows[0]["opcode"] == 1
    assert rows[1]["encoding"] == "base64" and rows[1]["bytes"] == 2

    (tmp_path / "flows.jsonl").write_text(
        json.dumps(_row("https://a.example/socket", status=101, ident="ws-1"))
        + "\n"
        + json.dumps(_row("https://a.example/other", ident="x"))
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / WS_NAME).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    assert write_har(tmp_path / "flows.jsonl", tmp_path / HAR_NAME) == 2
    entries = json.loads((tmp_path / HAR_NAME).read_text(encoding="utf-8"))["log"]["entries"]
    messages = entries[0]["_webSocketMessages"]
    assert [m["type"] for m in messages] == ["send", "receive"]
    assert messages[0]["data"] == "hello" and messages[1]["_encoding"] == "base64"
    assert entries[0]["_resourceType"] == "websocket"
    assert entries[0]["_oby"]["websocket"] == {"code": 1000, "reason": "bye", "by_client": True, "time": 5.0}
    assert "_webSocketMessages" not in entries[1]
    assert not (tmp_path / (HAR_NAME + ".part")).exists()


def test_an_event_stream_is_split_into_events():
    body = ": comment\r\nevent: tick\ndata: one\ndata: two\nid: 7\n\ndata:{\"a\":1}\n\nretry: 5\n"
    assert events(body) == [
        {"event": "tick", "id": "7", "data": "one\ntwo"},
        {"data": '{"a":1}'},
        {"retry": "5", "data": ""},
    ]
    entry = document([_row("https://a.example/sse", body=body, ctype="text/event-stream; charset=utf-8")])["log"][
        "entries"
    ][0]
    assert len(entry["_oby"]["events"]) == 3
    assert entry["response"]["content"]["text"] == body


def test_each_navigation_is_a_page_and_a_redirect_stays_on_it():
    rows = [
        _row("https://firefox.example/startup"),
        _row("http://a.example/", status=301, navigate=True),
        _row("https://a.example/", navigate=True),
        _row("https://a.example/app.js"),
        _row("https://b.example/", navigate=True),
    ]
    pages, refs = assign_pages(rows)
    assert refs == ["page_1", "page_2", "page_2", "page_2", "page_3"]
    assert [page["title"] for page in pages] == [
        "https://firefox.example/startup",
        "https://a.example/",
        "https://b.example/",
    ]
    log = document(rows)["log"]
    assert [entry["pageref"] for entry in log["entries"]] == refs


def test_a_recorded_visit_moves_to_history_and_an_empty_one_is_dropped(tmp_path: Path):
    from oby.proxy import reset_capture

    (tmp_path / "flows.jsonl").write_text('{"url":"https://old.example/"}\n', encoding="utf-8")
    (tmp_path / "session.har").write_text("{}", encoding="utf-8")
    (tmp_path / "meta.json").write_text('{"started_at": "2026-11-14T19:55:25.741486Z"}', encoding="utf-8")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "abc.js").write_text("1", encoding="utf-8")
    (tmp_path / "profile").mkdir()

    kept = reset_capture(tmp_path)
    assert kept == tmp_path / "history" / "2026-11-14T19-55-25"
    assert (kept / "flows.jsonl").read_text(encoding="utf-8").startswith('{"url":"https://old.example/"}')
    assert (kept / "session.har").exists() and (kept / "scripts" / "abc.js").exists()
    assert (tmp_path / "profile").is_dir()
    assert not (tmp_path / "flows.jsonl").exists() and not (tmp_path / "scripts").exists()

    # A launch that recorded nothing leaves no history behind, and costs none.
    (tmp_path / "flows.jsonl").write_text("\n", encoding="utf-8")
    (tmp_path / "session.har").write_text("{}", encoding="utf-8")
    assert reset_capture(tmp_path) is None
    assert not (tmp_path / "session.har").exists()
    assert [path.name for path in (tmp_path / "history").iterdir()] == ["2026-11-14T19-55-25"]

    # Two visits that began in the same second do not overwrite each other.
    (tmp_path / "flows.jsonl").write_text('{"url":"https://new.example/"}\n', encoding="utf-8")
    (tmp_path / "meta.json").write_text('{"started_at": "2026-11-14T19:55:25.9Z"}', encoding="utf-8")
    assert reset_capture(tmp_path).name == "2026-11-14T19-55-25-2"


def test_an_event_stream_is_relayed_and_each_event_keeps_its_arrival_time():
    from oby import stream
    from oby.record import body_field

    request = SimpleNamespace(
        headers={"accept": "text/event-stream"}, method="GET", raw_content=b""
    )
    assert stream.wants_stream(request)
    request.headers = {"accept": "text/html"}
    assert not stream.wants_stream(request)
    request.headers = {"accept": "text/event-stream", "Sec-WebSocket-Version": "13"}
    assert not stream.wants_stream(request)
    request.headers = {"accept": "text/event-stream"}
    request.method, request.raw_content = "POST", b"\xff\xfe"
    assert not stream.wants_stream(request)

    chunks = [
        (1.0, b"id: 1\ndata: one\n\n: keep-alive\n\nda"),
        (2.0, b"ta: two\r\n\r\n"),
        (3.0, b"data: cut off"),
    ]
    assert stream.events_with_times(chunks) == [1.0, 2.0]

    closed = []
    upstream = SimpleNamespace(status_code=200, protocol="h2", close=lambda: closed.append(True))
    token = stream.new_entry(
        upstream=upstream,
        flow=None,
        request_row={"id": "s", "url": "https://a.example/events", "method": "GET", "timing": {"request_start": 0.5, "request_end": 0.6}},
        headers=[["content-type", "text/event-stream"]],
        cloak={"via": "mirror", "streamed": True},
    )
    entry = stream.OPEN.pop(token)
    entry["chunks"].extend(chunks)
    stream.finish(entry)
    stream.finish(entry)
    assert closed == [True]
    row = stream.stream_row(entry, body_field)
    assert row["url"] == "https://a.example/events" and row["response_http_version"] == "HTTP/2.0"
    assert row["response_body"]["text"].endswith("data: cut off")
    assert row["stream"]["complete"] is False and len(row["stream"]["chunks"]) == 3

    built = document([row])["log"]["entries"][0]
    found = built["_oby"]["events"]
    assert [(e["data"], e.get("time")) for e in found] == [("one", 1.0), ("two", 2.0), ("cut off", None)]
    assert built["_oby"]["stream"]["complete"] is False and "event_times" not in built["_oby"]["stream"]
    assert built["_oby"]["mitmcloak"]["streamed"] is True


def test_mitmcloak_passes_over_a_flow_the_relay_opened():
    from oby import stream

    resolver = SimpleNamespace(should_bypass=lambda flow: False)
    bridge = SimpleNamespace(resolver=resolver)
    stream.leave_to_relay(bridge)
    stream.leave_to_relay(bridge)
    assert resolver.should_bypass(SimpleNamespace(metadata={"oby_stream": "token"})) is True
    assert resolver.should_bypass(SimpleNamespace(metadata={})) is False


def test_each_request_is_linked_to_the_script_frame_that_made_it(tmp_path: Path):
    from oby import initiators, query

    from oby import chrome

    def sent(request_id, url, method, kind, frame=None, document=None):
        initiator = {"type": "other"}
        if frame:
            name, line, column, function = frame
            initiator = {"type": "script", "stack": {"callFrames": [{"url": name, "lineNumber": line, "columnNumber": column, "functionName": function}]}}
        params = {"requestId": request_id, "type": kind, "request": {"url": url, "method": method}, "initiator": initiator}
        if document:
            params["documentURL"] = document
        return chrome.request_rows("S", "Network.requestWillBeSent", params, hops)

    hops: dict = {}
    lines = (
        sent("5", "https://a.example/", "GET", "Document")
        + sent("7", "https://a.example/api", "POST", "Fetch", ("https://a.example/app.js", 1, 26, "callApi"), "https://a.example/")
        # Made inside an eval: V8 names the eval's script, which has no URL of its own file.
        + sent("8", "https://a.example/api", "POST", "Fetch", ("https://a.example/app.js line 2 > eval", 0, 5, ""))
        + sent("9", "data:text/plain,x", "GET", "Fetch")
    )
    assert len(lines) == 5
    (tmp_path / "initiators.jsonl").write_text("".join(json.dumps(row) + "\n" for row in lines), encoding="utf-8")
    flows = [
        {"url": "https://startup.example/", "method": "GET", "status": 200},
        {"url": "https://a.example/", "method": "GET", "status": 200},
        {"url": "https://a.example/api", "method": "POST", "status": 200},
        {"url": "https://a.example/api", "method": "POST", "status": 200},
    ]
    (tmp_path / "flows.jsonl").write_text("".join(json.dumps(row) + "\n" for row in flows), encoding="utf-8")

    started = initiators.for_folder(tmp_path, flows)
    assert started[0] is None
    assert started[1] == {"type": "document"}
    assert started[2] == {
        "type": "fetch", "document": "https://a.example/",
        "url": "https://a.example/app.js", "line": 2, "column": 27, "function": "callApi",
    }
    assert started[3]["url"].endswith("> eval")

    write_har(tmp_path / "flows.jsonl", tmp_path / HAR_NAME)
    entries = json.loads((tmp_path / HAR_NAME).read_text(encoding="utf-8"))["log"]["entries"]
    assert "_initiator" not in entries[0]
    assert entries[1]["_initiator"] == {"type": "parser"}
    frame = entries[2]["_initiator"]["stack"]["callFrames"][0]
    assert frame == {"functionName": "callApi", "url": "https://a.example/app.js", "lineNumber": 1, "columnNumber": 26}
    assert entries[2]["_oby"]["initiator"]["line"] == 2

    listed = query.exchanges(tmp_path)["exchanges"]
    assert listed[2]["initiator"] == "https://a.example/app.js:2:27 callApi"
    assert "initiator" not in listed[1]
    assert query.exchange(tmp_path, 3)["initiator"]["line"] == 1


def test_every_request_with_a_text_body_is_opened_as_a_stream():
    from oby import stream

    def request(method, body=b"", **headers):
        return SimpleNamespace(headers=headers, method=method, raw_content=body)

    assert stream.wants_relay(request("GET"))
    assert stream.wants_relay(request("POST", b'{"a": 1}'))
    assert stream.wants_relay(request("DELETE"))
    # The streaming call takes the body as a string.
    assert not stream.wants_relay(request("POST", b"\xff\xfe"))
    assert not stream.wants_relay(request("HEAD"))
    assert not stream.wants_relay(request("GET", **{"Sec-WebSocket-Version": "13"}))


def test_a_body_the_browser_stopped_reading_is_cut_off_only_when_bytes_are_missing():
    from oby import stream

    def entry(status, headers, chunks):
        return {"status": status, "response_headers": headers, "chunks": [(1.0, chunk) for chunk in chunks]}

    assert stream.body_is_whole(entry(302, [["Location", "/next"]], []))
    assert stream.body_is_whole(entry(200, [["Content-Length", "5"]], [b"he", b"llo"]))
    assert not stream.body_is_whole(entry(200, [["Content-Length", "9"]], [b"hello"]))
    assert not stream.body_is_whole(entry(200, [], [b"hello"]))
    # The length is of the compressed bytes, and these were decoded on the way.
    assert not stream.body_is_whole(entry(200, [["Content-Length", "5"], ["Content-Encoding", "br"]], [b"hello"]))
