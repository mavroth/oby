"""WebAssembly capture, the fingerprint log, and the readable views of a script."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from oby import chrome, deob, fingerprint, query, wasm
from oby.scripts import write_scripts

# (module (func (export "add") (param i32 i32) (result i32) local.get 0 local.get 1 i32.add))
ADD = bytes([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 3, 2, 1, 0, 7, 7, 1, 3, 97, 100, 100, 0, 0, 10, 9, 1, 7, 0, 32, 0, 32, 1, 106, 11])
# The same, importing env.log as a function of type 0 first.
IMPORTING = bytes([0, 97, 115, 109, 1, 0, 0, 0, 1, 7, 1, 96, 2, 127, 127, 1, 127, 2, 11, 1, 3, 101, 110, 118, 3, 108, 111, 103, 0, 0, 3, 2, 1, 0, 7, 7, 1, 3, 97, 100, 100, 0, 1, 10, 9, 1, 7, 0, 32, 0, 32, 1, 106, 11])


def test_a_wasm_module_is_described_by_what_it_imports_and_exports():
    assert wasm.describe(ADD) == {"imports": [], "exports": [{"name": "add", "kind": "function"}], "functions": 1}
    described = wasm.describe(IMPORTING)
    assert described["imports"] == [{"module": "env", "name": "log", "kind": "function"}]
    assert described["exports"] == [{"name": "add", "kind": "function"}]
    assert wasm.describe(b"not a module") == {}
    # Damage part way through keeps what was read before it.
    assert wasm.describe(IMPORTING[:40])["imports"] == described["imports"]
    assert wasm.describe(IMPORTING[:40])["incomplete"] is True


def test_a_wasm_module_is_listed_with_the_scripts_and_written_as_its_bytes(tmp_path: Path):
    assert chrome.script_kind({"url": "wasm://wasm/49d0164e", "scriptLanguage": "WebAssembly"}) == "wasm"
    (tmp_path / "flows.jsonl").write_text("", encoding="utf-8")
    rows = [
        {"kind": "wasm", "url": "wasm://wasm/49d0164e", "bytecode": base64.b64encode(IMPORTING).decode(), "introduction": ""},
        {"kind": "network", "url": "https://a.example/app.js", "source": "run()", "introduction": ""},
    ]
    (tmp_path / "scripts-parsed.jsonl").write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    listed = query.scripts(tmp_path, kind="wasm")["scripts"]
    assert listed[0]["imports"] == 1 and listed[0]["exports"] == 1 and listed[0]["length"] == len(IMPORTING)
    # A module is searched by its names.
    assert query.scripts(tmp_path, contains="import env.log")["matched"] == 1
    assert query.scripts(tmp_path, contains="export add")["matched"] == 1
    detail = query.script(tmp_path, listed[0]["sha256"][:10])
    assert detail["exports"] == [{"name": "add", "kind": "function"}] and "source" not in detail

    assert write_scripts(tmp_path / "flows.jsonl", tmp_path / "scripts.json", tmp_path / "scripts-parsed.jsonl") == 2
    body = json.loads((tmp_path / "scripts.json").read_text(encoding="utf-8"))
    module = next(item for item in body["scripts"] if item["kind"] == "wasm")
    assert body["counts"] == {"wasm": 1, "network": 1}
    assert (tmp_path / module["file"]).read_bytes() == IMPORTING
    assert "bytecode" not in module


def test_the_obfuscators_spelling_is_undone_and_the_meaning_is_not_touched():
    source = (
        r"var a=['\x68\x65\x6c\x6c\x6f','lo'+'g'];function greet(n){var t=0x10+0x20;if(!![]){console['log'](a[0x0]+' '+'wor'+'ld',t,!0,void 0);}"
        r"return n/2/t;}var r=/['#]\x41+/g.test('x');var s=#it\x27s#;var u=x['class'];var k=y - 'a' + 'b';var l='a'+'b'.length; // 0x10 in a comment"
    ).replace("#", '"')
    text, made = deob.rewrite(source)
    assert "var a=['hello','log'];" in text
    assert "var t=16+32;if(true){console.log(a[0]+' world',t,true,undefined);}" in text
    # Left alone: a regular expression, a reserved word as a property, and joins that would change the result.
    assert "/['\"]\\x41+/g.test('x')" in text
    assert "x['class']" in text
    assert "y - 'a' + 'b'" in text
    assert "'a'+'b'.length" in text
    assert "// 0x10 in a comment" in text
    assert "\"it's\"" in text
    # `a` is built with a join, so it is not a plain list of strings, and its lookups stay.
    assert made["lookups"] == 0 and made["numbers"] == 3


def test_a_string_table_is_inlined_only_when_the_script_never_reorders_or_changes_it():
    plain = "var t=['token','/api'];send(t[0],t[1]);"
    assert deob.rewrite(plain)[0] == "var t=['token','/api'];send('token','/api');"
    # Handed to a function: an obfuscator rotates it there, so an index no longer means what it says.
    rotated = "var t=['a','b'];(function(x){x.push(x.shift())})(t);log(t[0]);"
    assert deob.rewrite(rotated)[0] == rotated
    written = "var w=['p','q'];w[0]='z';log(w[0]);"
    assert deob.rewrite(written)[0] == written
    measured = "var m=['p','q'];log(m[0],m.length);"
    assert deob.rewrite(measured)[0] == measured


def test_the_formatter_never_drops_a_declaration():
    text = deob.pretty("var _0xa=['token','/api'];fetch(_0xa[1]);")
    assert "var _0xa = ['token', '/api'];" in text and "fetch(_0xa[1]);" in text


def test_a_script_is_read_and_searched_in_any_view_and_the_views_are_kept_beside_it(tmp_path: Path):
    source = r"var _0xa=['\x74\x6f\x6b\x65\x6e'];function sign(v){if(!![]){return window['btoa'](v+'-'+'se'+'cret'+0x1f);}}sign(_0xa[0x0]);"
    (tmp_path / "flows.jsonl").write_text("", encoding="utf-8")
    (tmp_path / "scripts-parsed.jsonl").write_text(
        json.dumps({"kind": "network", "url": "https://a.example/obf.js", "source": source, "introduction": ""}) + "\n", encoding="utf-8"
    )
    found = query.scripts(tmp_path, contains=r"_0x[a-f0-9]+\[", regex=True)
    assert found["matched"] == 1 and found["scripts"][0]["matches"] == 1
    sha = found["scripts"][0]["sha256"]
    try:
        query.scripts(tmp_path, contains="(", regex=True)
    except ValueError as exc:
        assert "does not compile" in str(exc)
    else:
        raise AssertionError("a broken expression was accepted")

    assert query.script(tmp_path, sha)["source"] == source
    readable = query.script(tmp_path, sha, view="deobfuscated")
    assert "return window.btoa(v + '-secret' + 31);" in readable["source"]
    assert "sign('token');" in readable["source"]
    assert (tmp_path / readable["file"]).read_text(encoding="utf-8") == readable["source"]
    hit = query.script(tmp_path, sha, view="deobfuscated", find="secret", context=1)
    assert hit["matching_lines"] == 1
    assert hit["lines"][0]["text"].splitlines()[1].strip() == "return window.btoa(v + '-secret' + 31);"
    # The original search still finds nothing readable there.
    assert query.script(tmp_path, sha, find="-secret")["matching_lines"] == 0
    assert "error" in query.script(tmp_path, sha, view="nope")


def test_fingerprint_reports_become_a_summary_by_api_and_by_script(tmp_path: Path):
    assert fingerprint.category_of("HTMLCanvasElement.toDataURL") == "canvas"
    assert fingerprint.category_of("devicePixelRatio") == "screen"
    source = fingerprint.hook_source()
    assert "HTMLCanvasElement.prototype" in source and "__TARGETS__" not in source
    # The hook keeps its log to itself: no network, no console, no global.
    for word in ("fetch(", "XMLHttpRequest", "console.", "postMessage", "window.__"):
        assert word not in source
    assert chrome.is_driver_source(source)

    frame = {"url": "https://a.example/fp.js", "line": 5, "column": 18, "function": "collect"}
    report = json.dumps({
        "url": "https://a.example/",
        "rows": [
            {"api": "HTMLCanvasElement.toDataURL", "n": 1, "time": 1.0, "at": frame, "result": {"length": 3558, "fnv1a": "8a32e210"}},
            {"api": "Navigator.userAgent", "n": 1, "time": 1.1, "at": frame, "result": "Mozilla/5.0"},
            {"api": "Navigator.userAgent", "n": 2, "time": 1.2, "at": {"url": "https://b.example/t.js", "line": 1, "column": 1}},
        ],
        "counts": {"HTMLCanvasElement.toDataURL": 1, "Navigator.userAgent": 2, "Performance.now": 900},
    })
    rows = fingerprint.rows_from_report(report)
    assert len(rows) == 4 and rows[0]["page"] == "https://a.example/"
    assert fingerprint.rows_from_report("not json") == []
    (tmp_path / fingerprint.LOG_NAME).write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    assert fingerprint.write_summary(tmp_path) == 903
    body = json.loads((tmp_path / fingerprint.SUMMARY_NAME).read_text(encoding="utf-8"))
    assert [item["api"] for item in body["apis"]] == ["Performance.now", "Navigator.userAgent", "HTMLCanvasElement.toDataURL"]
    assert body["categories"] == {"runtime": 900, "navigator": 2, "canvas": 1}
    assert body["scripts"][0] == {"url": "https://a.example/fp.js", "apis": {"HTMLCanvasElement.toDataURL": 1, "Navigator.userAgent": 1}}

    asked = query.fingerprint(tmp_path, category="canvas")
    assert [item["api"] for item in asked["apis"]] == ["HTMLCanvasElement.toDataURL"]
    assert asked["apis"][0]["calls"][0]["result"]["fnv1a"] == "8a32e210"
    assert [item["api"] for item in query.fingerprint(tmp_path, script="b.example")["apis"]] == ["Navigator.userAgent"]
    assert "--fingerprints" in query.fingerprint(tmp_path / "empty")["note"]


def test_the_watch_puts_code_in_a_page_only_when_fingerprints_were_asked_for(tmp_path: Path):
    def armed(fingerprints: bool) -> list[str]:
        watch = chrome.Watch(0, tmp_path, fingerprints=fingerprints)
        sent: list[str] = []
        watch._send = lambda method, params=None, session=None, then=None: sent.append(method)
        watch._arm("S", "page")
        watch._arm("W", "worker")
        return sent

    assert "Page.addScriptToEvaluateOnNewDocument" not in armed(False)
    assert "Runtime.enable" not in armed(False)
    on = armed(True)
    # Once, for the page. A worker has no document to run it in.
    assert on.count("Page.addScriptToEvaluateOnNewDocument") == 1


def test_the_watch_reads_the_log_from_each_frame_and_before_a_page_leaves(tmp_path: Path):
    watch = chrome.Watch(0, tmp_path, fingerprints=True)
    sent: list[tuple] = []

    def send(method, params=None, session=None, then=None):
        sent.append((method, params or {}, then))
        return len(sent)

    watch._send = send
    for number, default in ((3, True), (4, False), (5, True)):
        watch._handle({"method": "Runtime.executionContextCreated", "sessionId": "S",
                       "params": {"context": {"id": number, "auxData": {"isDefault": default}}}})
    # A navigation is about to replace the document, and its log with it.
    watch._handle({"method": "Network.requestWillBeSent", "sessionId": "S",
                   "params": {"requestId": "1", "type": "Document", "request": {"url": "https://a.example/next", "method": "GET"}}})
    asked = [(method, params.get("contextId")) for method, params, _then in sent if method == "Runtime.evaluate"]
    assert asked == [("Runtime.evaluate", 3), ("Runtime.evaluate", 5)]

    # Follow one read through: the wrapped member, its handler, then the log.
    sent[0][2]({"result": {"result": {"type": "object", "subtype": "proxy", "objectId": "P"}}})
    assert sent[-1][0] == "Runtime.getProperties" and sent[-1][1]["objectId"] == "P"
    sent[-1][2]({"result": {"internalProperties": [{"name": "[[Handler]]", "value": {"objectId": "H"}}]}})
    assert sent[-1][0] == "Runtime.callFunctionOn" and sent[-1][1]["objectId"] == "H"
    report = json.dumps({"url": "https://a.example/", "rows": [{"api": "Screen.width", "n": 1}], "counts": {"Screen.width": 1}})
    sent[-1][2]({"result": {"result": {"type": "string", "value": report}}})
    rows = fingerprint.read(tmp_path / fingerprint.LOG_NAME)
    assert rows[0]["api"] == "Screen.width" and rows[1]["counts"] == {"Screen.width": 1}

    watch._handle({"method": "Runtime.executionContextDestroyed", "sessionId": "S", "params": {"executionContextId": 3}})
    assert watch._worlds["S"] == {5}
