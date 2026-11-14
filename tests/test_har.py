import json
from pathlib import Path

from oby.har import HAR_NAME, document, write_har
from oby.record import exchange


class _Headers:
    def __init__(self, fields):
        self.fields = fields


class _Message:
    def __init__(self, raw, headers, status=None):
        self.raw_content = raw
        self.content = raw
        self.headers = headers
        self.http_version = "HTTP/2.0"
        self.status_code = status


class _Flow:
    def __init__(self):
        self.request = _Message(
            b'{"a":1}',
            _Headers([(b"Cookie", b"a=1"), (b"X-Odd", b"1"), (b"Cookie", b"b=2")]),
        )
        self.request.pretty_url = "https://example.com/api?q=1"
        self.request.method = "POST"
        self.response = _Message(
            b"ok",
            _Headers(
                [
                    (b"content-type", b"text/plain"),
                    (b"set-cookie", b"sid=abc; Path=/; HttpOnly; Secure"),
                ]
            ),
            status=200,
        )
        self.error = None
        self.metadata = {"mitmcloak": {"via": "mirror"}}


def test_har_keeps_order_duplicates_body_and_preface(tmp_path: Path):
    row = exchange(_Flow())
    row["started"] = 1_700_000_000.0
    row["ended"] = 1_700_000_000.25
    row["http2"] = {"pseudo_order": [":method", ":path", ":authority", ":scheme"], "settings": [[1, 65536]]}
    source = tmp_path / "flows.jsonl"
    source.write_text(json.dumps(row) + "\n" + "not json\n", encoding="utf-8")
    dest = tmp_path / HAR_NAME
    assert write_har(source, dest) == 1

    log = json.loads(dest.read_text(encoding="utf-8"))["log"]
    assert log["version"] == "1.2"
    assert log["creator"]["name"] == "oby"
    entry = log["entries"][0]
    names = [header["name"] for header in entry["request"]["headers"]]
    assert names[:3] == ["Cookie", "X-Odd", "Cookie"]
    assert [header["value"] for header in entry["request"]["headers"] if header["name"] == "Cookie"] == [
        "a=1",
        "b=2",
    ]
    assert entry["request"]["cookies"] == [{"name": "a", "value": "1"}, {"name": "b", "value": "2"}]
    assert entry["request"]["queryString"] == [{"name": "q", "value": "1"}]
    assert entry["request"]["postData"]["text"] == '{"a":1}'
    assert entry["response"]["status"] == 200
    assert entry["response"]["content"]["text"] == "ok"
    assert entry["response"]["cookies"][0]["name"] == "sid"
    assert entry["response"]["cookies"][0]["httpOnly"] is True
    assert entry["_oby"]["http2"]["pseudo_order"][0] == ":method"
    assert entry["_oby"]["mitmcloak"]["via"] == "mirror"
    assert entry["time"] == 250
    assert "proxy-authorization" not in json.dumps(entry["request"]).lower()


def test_har_document_is_empty_but_valid():
    log = document([])["log"]
    assert log["entries"] == []
    assert log["pages"][0]["id"] == "page_1"
    assert log["pages"][0]["startedDateTime"].endswith("Z")


def test_a_new_visit_starts_from_an_empty_capture(tmp_path: Path):
    from oby.proxy import reset_capture

    (tmp_path / "flows.jsonl").write_text('{"url":"https://old.example/"}\n', encoding="utf-8")
    (tmp_path / "scripts-parsed.jsonl").write_text("{}\n", encoding="utf-8")
    (tmp_path / "scripts-live.jsonl").write_text("{}\n", encoding="utf-8")
    (tmp_path / "scripts.json").write_text("{}", encoding="utf-8")
    (tmp_path / "session.har").write_text("{}", encoding="utf-8")
    reset_capture(tmp_path)
    for name in (
        "flows.jsonl",
        "scripts-parsed.jsonl",
        "scripts-live.jsonl",
        "scripts.json",
        "session.har",
    ):
        assert not (tmp_path / name).exists()


def test_exchange_records_timestamps():
    flow = _Flow()
    flow.request.timestamp_start = 10.0
    flow.request.timestamp_end = 10.1
    flow.response.timestamp_end = 10.4
    row = exchange(flow)
    assert row["started"] == 10.0
    assert row["ended"] == 10.4


def test_recording_report_counts_flows_and_hides_values(tmp_path: Path, monkeypatch):
    (tmp_path / "flows.jsonl").write_text('{"url":"https://example.com","cookie":"secret"}\n\n', encoding="utf-8")
    monkeypatch.setenv("OBY_OUT", str(tmp_path))
    monkeypatch.setenv("OBY_HOST_OUT", "/sessions/demo")
    from oby.mcp import recording_report

    report = recording_report()
    assert report["output_dir"] == "/sessions/demo"
    assert report["har"] == "/sessions/demo/session.har"
    assert report["har_ready"] is False
    assert report["flows_so_far"] == 1
    assert "secret" not in json.dumps(report)


def test_mcp_is_told_the_session_ends_as_a_har():
    from invisible_playwright_mcp.mcp import server as mcp_server

    from oby.mcp import teach

    teach(mcp_server)
    teach(mcp_server)
    instructions = mcp_server.mcp._mcp_server.instructions
    assert instructions.count("session.har") == 1 or "session.har" in instructions
    assert instructions.count("The file to take away is session.har.") == 1
    names = [tool.name for tool in mcp_server.mcp._tool_manager.list_tools()]
    assert names.count("oby_recording") == 1
