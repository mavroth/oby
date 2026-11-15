"""An agent reads the recording while the visit runs."""

import asyncio
import json
from pathlib import Path

from oby import query


def _write(folder: Path) -> None:
    flows = [
        {
            "id": "a",
            "url": "https://shop.example/",
            "method": "GET",
            "status": 200,
            "request_headers": [["Cookie", "sid=topsecret"]],
            "response_headers": [["content-type", "text/html"]],
            "response_body": {"text": "<html></html>", "encoding": "utf-8", "bytes": 13},
        },
        {
            "id": "b",
            "url": "https://api.shop.example/sensor",
            "method": "POST",
            "status": 201,
            "request_headers": [["content-type", "application/json"]],
            "request_body": {"text": '{"sensor_data":"' + "x" * 500 + '"}', "encoding": "utf-8", "bytes": 518},
            "response_headers": [["content-type", "application/json"]],
            "response_body": {"text": '{"ok":true}', "encoding": "utf-8", "bytes": 11},
            "request_header_block": "content-type: application/json\r\n",
        },
        {
            "id": "c",
            "url": "https://api.shop.example/live",
            "method": "GET",
            "status": 101,
            "request_headers": [],
            "response_headers": [],
        },
    ]
    (folder / "flows.jsonl").write_text("".join(json.dumps(row) + "\n" for row in flows), encoding="utf-8")
    sockets = [
        {"id": "c", "from_client": True, "opcode": 1, "bytes": 4, "time": 1.0, "text": "ping"},
        {"id": "c", "from_client": False, "opcode": 1, "bytes": 4, "time": 2.0, "text": "pong"},
        {"id": "c", "closed": True, "code": 1000},
    ]
    (folder / "ws.jsonl").write_text("".join(json.dumps(row) + "\n" for row in sockets), encoding="utf-8")
    parsed = [
        {"kind": "network", "url": "https://shop.example/app.js", "source": "var a = 1; function bmak(){ return a }"},
        {"kind": "eval", "url": "", "source": "bmak(); bmak();", "introduction": "eval"},
    ]
    (folder / "scripts-parsed.jsonl").write_text("".join(json.dumps(row) + "\n" for row in parsed), encoding="utf-8")


def test_exchanges_are_listed_and_filtered_without_bodies(tmp_path: Path):
    _write(tmp_path)
    everything = query.exchanges(tmp_path)
    assert everything["total"] == 3 and everything["matched"] == 3
    assert "topsecret" not in json.dumps(everything)
    assert everything["exchanges"][2]["websocket_messages"] == 2

    posts = query.exchanges(tmp_path, host="api.shop", method="post")
    assert [row["index"] for row in posts["exchanges"]] == [1]
    assert query.exchanges(tmp_path, contains="SENSOR_DATA")["matched"] == 1
    assert query.exchanges(tmp_path, status=101)["exchanges"][0]["url"].endswith("/live")
    assert query.exchanges(tmp_path, offset=1, limit=1)["exchanges"][0]["index"] == 1


def test_one_exchange_returns_its_content_clipped_to_what_was_asked(tmp_path: Path):
    _write(tmp_path)
    row = query.exchange(tmp_path, 1, max_body=40)
    assert row["request_body"]["text"].startswith('{"sensor_data":"x')
    assert len(row["request_body"]["text"]) == 40
    assert row["request_body"]["total_chars"] == 518
    assert row["response_body"]["text"] == '{"ok":true}'
    assert "request_header_block" not in row
    assert "error" in query.exchange(tmp_path, 9)


def test_websocket_messages_are_read_by_handshake_index(tmp_path: Path):
    _write(tmp_path)
    result = query.messages(tmp_path, 2)
    assert [(m["direction"], m["text"]) for m in result["messages"]] == [("send", "ping"), ("receive", "pong")]
    assert result["closed"] == {"code": 1000}
    assert query.messages(tmp_path, 0)["total"] == 0


def test_scripts_are_searched_and_sliced(tmp_path: Path):
    _write(tmp_path)
    listed = query.scripts(tmp_path)
    assert listed["total"] == 2 and "source" not in listed["scripts"][0]
    found = query.scripts(tmp_path, contains="BMAK")
    assert [row["matches"] for row in found["scripts"]] == [1, 2]
    assert "bmak" in found["scripts"][0]["snippets"][0]["text"]
    assert query.scripts(tmp_path, kind="eval")["matched"] == 1

    digest = found["scripts"][0]["sha256"]
    piece = query.script(tmp_path, digest[:10], offset=4, length=5)
    assert piece["source"] == "a = 1" and piece["total_chars"] == 38
    assert "error" in query.script(tmp_path, "zz")


def test_save_writes_the_har_the_scripts_and_a_file_per_script(tmp_path: Path):
    _write(tmp_path)
    assert query.save(tmp_path) == {"exchanges": 3, "scripts": 2}
    har = json.loads((tmp_path / "session.har").read_text(encoding="utf-8"))
    assert len(har["log"]["entries"][2]["_webSocketMessages"]) == 2
    listed = json.loads((tmp_path / "scripts.json").read_text(encoding="utf-8"))
    for item in listed["scripts"]:
        assert (tmp_path / item["file"]).read_text(encoding="utf-8") == item["source"]
    # The visit goes on, and a later save sees what arrived since.
    with (tmp_path / "flows.jsonl").open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"id": "d", "url": "https://shop.example/late", "status": 200}) + "\n")
    assert query.save(tmp_path)["exchanges"] == 4


def test_a_long_script_is_not_cut(tmp_path: Path):
    from oby.scripts import write_scripts

    source = "x=1;" * 3_000_000
    (tmp_path / "scripts-parsed.jsonl").write_text(
        json.dumps({"kind": "network", "url": "https://a.example/big.js", "source": source}) + "\n",
        encoding="utf-8",
    )
    write_scripts(tmp_path / "flows.jsonl", tmp_path / "scripts.json", tmp_path / "scripts-parsed.jsonl")
    item = json.loads((tmp_path / "scripts.json").read_text(encoding="utf-8"))["scripts"][0]
    assert item["length"] == len(source) and "truncated" not in item


def test_storage_is_saved_from_the_agents_browser(tmp_path: Path, monkeypatch):
    from oby import storage

    class _Context:
        async def storage_state(self):
            return {"cookies": [{"name": "sid", "value": "1"}], "origins": [{"origin": "https://a.example"}]}

    class _Browser:
        contexts = [_Context()]

    monkeypatch.setattr(storage, "_live", [])
    monkeypatch.setenv("OBY_OUT", str(tmp_path))
    assert asyncio.run(storage.save_async()) is None
    storage.remember(_Context())
    storage.remember(_Browser())
    assert asyncio.run(storage.save_async()) == {"cookies": 2, "origins": 2}
    saved = json.loads((tmp_path / "storage.json").read_text(encoding="utf-8"))
    assert saved["cookies"][0]["name"] == "sid"


def test_the_agent_is_given_the_query_tools(tmp_path: Path, monkeypatch):
    from oby import mcp as oby_mcp
    from oby.proxy import Mitm

    server = oby_mcp.build_server(oby_mcp.Browser(tmp_path, Mitm(tmp_path), headless=True))
    names = [tool.name for tool in server._tool_manager.list_tools()]
    for name in ("oby_exchanges", "oby_exchange", "oby_messages", "oby_scripts", "oby_script", "oby_save", "oby_recording"):
        assert names.count(name) == 1
    for name in ("browser_open", "browser_navigate", "browser_snapshot", "browser_click", "browser_type"):
        assert names.count(name) == 1
    assert "The file to take away is session.har" in server.instructions
    assert "browser_snapshot" in server.instructions

    _write(tmp_path)
    monkeypatch.setenv("OBY_OUT", str(tmp_path))
    assert json.loads(oby_mcp.exchanges(method="POST"))["matched"] == 1
    assert json.loads(oby_mcp.script("nope"))["error"]
    saved = json.loads(asyncio.run(oby_mcp.save()))
    assert saved["exchanges"] == 3 and saved["scripts"] == 2
    assert oby_mcp.recording_report()["websocket_messages_so_far"] == 2
