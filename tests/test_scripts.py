import asyncio
import json
from pathlib import Path

from mitmproxy.flowfilter import parse
from mitmproxy.http import Headers
from mitmproxy.test.tflow import tflow
from mitmproxy.test.tutils import treq, tresp

from oby import collect, record
from oby.har import document
from oby.mcp import recording, recording_report, teach
from oby.proxy import build_mitmdump_command, cloak_addon_path
from oby.record import Record
from oby.scripts import (
    SAVE_FILTER,
    SINK_HOST,
    SINK_ORIGIN,
    SINK_URL,
    WATCH_SOURCE,
    _arm,
    _arm_sync,
    allow_script_report,
    answer_sink,
    append_report,
    install_script_watcher,
    relax_policy,
    write_scripts,
)


HTML = (
    b"<html><meta http-equiv=\"Content-Security-Policy\" content=\"connect-src 'self'\">"
    b"<script>var ran = 1</script>"
    b"<script src=\"/a.js\"></script>"
    b"<script type=\"application/json\">{\"n\":1}</script>"
    b"<script type=\"module\">var mod = 2</script>"
    b"</html>"
)
SECRET = "super-secret-cookie"
EVAL = "oby-eval-marker"


def _page():
    return tflow(
        req=treq(host="example.com", port=443, scheme=b"https", path=b"/", method=b"GET"),
        resp=tresp(
            status_code=200,
            headers=Headers(
                [
                    (b"content-type", b"text/html"),
                    (b"content-security-policy", b"connect-src 'self'"),
                    (b"set-cookie", b"sid=" + SECRET.encode()),
                ]
            ),
            content=HTML,
        ),
    )


def _script():
    return tflow(
        req=treq(host="example.com", port=443, scheme=b"https", path=b"/app.js", method=b"GET"),
        resp=tresp(
            status_code=200,
            headers=Headers([(b"content-type", b"application/javascript")]),
            content=b"globalThis.obyNet = 1;\n",
        ),
    )


def _sink():
    body = json.dumps({"kind": "eval", "source": EVAL, "url": "https://example.com/"}).encode()
    return tflow(
        req=treq(
            host=SINK_HOST,
            port=443,
            scheme=b"https",
            path=b"/collect",
            method=b"POST",
            headers=Headers(
                [
                    (b"content-type", b"text/plain"),
                    (b"content-length", str(len(body)).encode()),
                ]
            ),
            content=body,
        )
    )


def test_executed_scripts_include_network_inline_and_eval(tmp_path: Path, monkeypatch):
    flows = tmp_path / "flows.jsonl"
    live = tmp_path / "scripts-live.jsonl"
    monkeypatch.setenv("OBY_RECORD", str(flows))
    monkeypatch.setenv("OBY_SCRIPTS", str(live))
    page = _page()
    try:
        Record().response(page)
        Record().response(_script())
        sink = _sink()
        assert answer_sink(sink) is True
        Record().request(sink)
        Record().response(sink)
        append_report(sink.request.content, str(live))
    finally:
        Record().done()

    saved = flows.read_text(encoding="utf-8")
    assert SINK_HOST not in saved
    assert EVAL not in saved
    assert "connect-src 'self'" in saved
    assert SECRET in saved
    assert SINK_ORIGIN in page.response.headers.get("content-security-policy")
    assert SINK_ORIGIN.encode() in page.response.content
    assert sink.response.status_code == 204

    dest = tmp_path / "scripts.json"
    assert write_scripts(flows, live, dest) == 4
    text = dest.read_text(encoding="utf-8")
    assert SECRET not in text
    assert SINK_HOST not in text
    body = json.loads(text)
    kinds = [item["kind"] for item in body["scripts"]]
    assert kinds == ["inline", "inline", "network", "eval"]
    sources = [item["source"] for item in body["scripts"]]
    assert "var ran = 1" in sources[0]
    assert "var mod = 2" in sources[1]
    assert "obyNet" in sources[2]
    assert sources[3] == EVAL
    assert body["scripts"][3]["count"] == 2
    assert "scripts.json" in document([])["log"]["_oby"]["scripts"]


def test_a_live_debugger_leaves_the_policy(tmp_path: Path, monkeypatch):
    flag = tmp_path / "debugger.ready"
    flag.write_text("ok\n", encoding="utf-8")
    monkeypatch.setenv("OBY_PARSED_FLAG", str(flag))
    page = _page()
    allow_script_report(page)
    assert page.response.headers.get("content-security-policy") == "connect-src 'self'"


def test_policy_gains_the_collector_once():
    once = relax_policy("connect-src 'self'")
    assert once == f"connect-src 'self' {SINK_ORIGIN}"
    assert relax_policy(once) == once
    widened = relax_policy("default-src 'self'")
    assert widened.startswith("default-src 'self'")
    assert f"connect-src 'self' {SINK_ORIGIN}" in widened
    assert relax_policy("default-src 'none'") == f"default-src 'none'; connect-src {SINK_ORIGIN}"
    assert relax_policy("upgrade-insecure-requests") == "upgrade-insecure-requests"


def test_collector_stays_out_of_the_saved_flows():
    filt = parse(SAVE_FILTER)
    assert filt(_script())
    assert not filt(_sink())


def test_collector_addon_is_loaded_before_mitmcloak(tmp_path: Path):
    command = build_mitmdump_command(
        listen_port=9,
        confdir=tmp_path / "mitm",
        flow_path=tmp_path / "flows.mitm",
        export_dir=tmp_path / "presets",
        catalogue_dir=tmp_path / "seen",
        upstream=None,
    )
    collect_at = command.index(str(Path(collect.__file__).resolve()))
    cloak_at = command.index(cloak_addon_path())
    record_at = command.index(str(Path(record.__file__).resolve()))
    assert collect_at < cloak_at < record_at
    assert command[-1] == SAVE_FILTER


def test_watcher_is_installed_on_the_context():
    seen = []

    class Ctx:
        def add_init_script(self, script):
            seen.append(script)
            return "handle"

    ctx = Ctx()
    _arm_sync(ctx)
    _arm_sync(ctx)
    assert seen == [WATCH_SOURCE]
    assert SINK_URL in WATCH_SOURCE
    assert "function eval" in WATCH_SOURCE
    assert "wrapCtor(\"Worker\")" in WATCH_SOURCE
    assert "createObjectURL" in WATCH_SOURCE
    assert ctx._oby_script_handle == "handle"

    async def check():
        box = []

        class AsyncCtx:
            async def add_init_script(self, script):
                box.append(script)
                return "async-handle"

        async_ctx = AsyncCtx()
        await _arm(async_ctx)
        await _arm(async_ctx)
        assert box == [WATCH_SOURCE]
        assert async_ctx._oby_script_handle == "async-handle"

    asyncio.run(check())
    install_script_watcher()
    install_script_watcher()
    from invisible_playwright.async_api import InvisiblePlaywright as AsyncPW
    from invisible_playwright.launcher import InvisiblePlaywright as SyncPW

    assert SyncPW.__enter__._oby_scripts is True
    assert AsyncPW.__aenter__._oby_scripts is True
    assert SyncPW.__init__._oby_parsed is True
    assert AsyncPW.__init__._oby_parsed is True


def test_recording_report_counts_scripts_and_hides_source(tmp_path: Path, monkeypatch):
    (tmp_path / "flows.jsonl").write_text(
        json.dumps(
            {
                "url": "https://example.com/",
                "response_headers": [["content-type", "text/html"]],
                "response_body": {"text": "<script>SECRETSOURCE</script>", "encoding": "utf-8"},
            }
        )
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "scripts-live.jsonl").write_text(
        json.dumps({"kind": "eval", "source": "SECRETSOURCE", "url": "https://example.com/"}) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OBY_OUT", str(tmp_path))
    monkeypatch.setenv("OBY_HOST_OUT", "/sessions/demo")
    report = recording_report()
    assert report["scripts"] == "/sessions/demo/scripts.json"
    assert report["scripts_ready"] is False
    assert report["scripts_so_far"] == 2
    assert report["script_kinds"]["inline"] == 1
    assert report["script_kinds"]["eval"] == 1
    assert "SECRETSOURCE" not in json.dumps(report)
    assert len(recording.__doc__) < 1024
    from invisible_playwright_mcp.mcp import server as mcp_server

    teach(mcp_server)
    instructions = mcp_server.mcp._mcp_server.instructions
    assert "scripts.json" in instructions
    assert "Firefox reports each script it parses" in instructions
