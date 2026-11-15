"""scripts.json: the engine's parsed scripts, filled from the recording where the watch missed one."""

import json
from pathlib import Path

from oby.har import document
from oby.mcp import recording, recording_report
from oby.proxy import build_mitmdump_command, cloak_addon_path
from oby.scripts import PARSED_NOTE, WIRE_NOTE, write_scripts

JS = [["content-type", "text/javascript"]]


def _write(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_without_the_watch_the_list_is_the_files_and_inline_scripts_in_the_recording(tmp_path: Path):
    html = (
        '<html><script>var ran = 1</script><script src="/a.js"></script>'
        '<script type="application/json">{"n":1}</script><script type="module">var mod = 2</script></html>'
    )
    flows = tmp_path / "flows.jsonl"
    _write(flows, [
        {"url": "https://example.com/", "response_headers": [["content-type", "text/html"], ["set-cookie", "sid=SECRET"]],
         "response_body": {"text": html, "encoding": "utf-8"}},
        {"url": "https://example.com/app.js", "response_headers": JS, "response_body": {"text": "globalThis.obyNet = 1;\n", "encoding": "utf-8"}},
    ])
    dest = tmp_path / "scripts.json"
    assert write_scripts(flows, dest) == 3
    text = dest.read_text(encoding="utf-8")
    assert "SECRET" not in text
    body = json.loads(text)
    assert [item["kind"] for item in body["scripts"]] == ["inline", "inline", "network"]
    assert body["note"] == WIRE_NOTE
    assert body["counts"] == {"inline": 2, "network": 1}
    assert (tmp_path / body["scripts"][2]["file"]).read_text(encoding="utf-8") == "globalThis.obyNet = 1;\n"
    assert "scripts.json" in document([])["log"]["_oby"]["scripts"]


def test_parsed_scripts_replace_the_wire_copy_and_stay_whole(tmp_path: Path):
    flows = tmp_path / "flows.jsonl"
    _write(flows, [{"url": "https://example.com/", "response_headers": [["content-type", "text/html"]],
                    "response_body": {"text": "<script>WIRE</script>", "encoding": "utf-8"}}])
    source = "vendor-marker" + ("x" * 600_000) + "vendor-end-marker"
    parsed = tmp_path / "scripts-parsed.jsonl"
    _write(parsed, [{"kind": "network", "url": "https://cdn.example/react-vendors.js", "source": source, "introduction": ""}])
    dest = tmp_path / "scripts.json"
    assert write_scripts(flows, dest, parsed) == 1
    body = json.loads(dest.read_text(encoding="utf-8"))
    item = body["scripts"][0]
    assert item["length"] == len(source)
    assert item["source"].endswith("vendor-end-marker")
    assert "truncated" not in item
    assert "WIRE" not in dest.read_text(encoding="utf-8")
    assert body["note"] == PARSED_NOTE


def test_a_parsed_script_whose_text_never_came_is_taken_from_the_wire(tmp_path: Path):
    flows = tmp_path / "flows.jsonl"
    _write(flows, [
        {"url": "https://cdn.example/app.js", "response_headers": JS, "response_body": {"text": "APP()", "encoding": "utf-8"}},
        {"url": "https://cdn.example/never-ran.js", "response_headers": JS, "response_body": {"text": "NEVER()", "encoding": "utf-8"}},
        {"url": "https://cdn.example/cut.js", "response_headers": JS, "response_body": {"text": "CUT()", "encoding": "utf-8"}},
    ])
    parsed = tmp_path / "scripts-parsed.jsonl"
    _write(parsed, [
        {"kind": "network", "url": "https://cdn.example/first.js", "source": "FIRST()", "introduction": ""},
        {"kind": "network", "url": "https://cdn.example/app.js", "introduction": "", "unfetched": True},
        {"kind": "eval", "url": "", "introduction": "", "unfetched": True},
        {"kind": "network", "url": "https://cdn.example/cut.js", "source": "CU", "introduction": "", "truncated": True},
    ])
    dest = tmp_path / "scripts.json"
    assert write_scripts(flows, dest, parsed) == 3
    items = {item["url"]: item for item in json.loads(dest.read_text(encoding="utf-8"))["scripts"]}
    assert items["https://cdn.example/cut.js"]["source"] == "CUT()" and "truncated" not in items["https://cdn.example/cut.js"]
    assert items["https://cdn.example/app.js"]["source"] == "APP()"
    assert items["https://cdn.example/app.js"]["from"] == "wire"
    assert "from" not in items["https://cdn.example/first.js"]
    # Downloaded, with nothing saying it was fetched to run: not a script that ran.
    assert "https://cdn.example/never-ran.js" not in items


def test_a_file_fetched_to_run_that_the_engine_never_named_is_listed_as_unreported(tmp_path: Path):
    def row(name, dest, status=200):
        return {
            "url": f"https://cdn.example/{name}.js",
            "status": status,
            "request_headers": [["Host", "cdn.example"], ["Sec-Fetch-Dest", dest]],
            "response_headers": JS,
            "response_body": {"text": f"{name.upper()}()", "encoding": "utf-8"},
        }

    flows = tmp_path / "flows.jsonl"
    _write(flows, [row("named", "script"), row("missed", "script"), row("worker", "worker"), row("data", "empty"), row("gone", "script", 404)])
    parsed = tmp_path / "scripts-parsed.jsonl"
    _write(parsed, [{"kind": "network", "url": "https://cdn.example/named.js", "source": "NAMED()", "introduction": ""}])
    dest = tmp_path / "scripts.json"
    assert write_scripts(flows, dest, parsed) == 3
    items = {item["url"].rsplit("/", 1)[-1]: item for item in json.loads(dest.read_text(encoding="utf-8"))["scripts"]}
    assert set(items) == {"named.js", "missed.js", "worker.js"}
    assert "reported" not in items["named.js"] and "from" not in items["named.js"]
    assert items["missed.js"]["from"] == "wire" and items["missed.js"]["reported"] is False
    assert items["missed.js"]["source"] == "MISSED()"


def test_the_stream_addon_is_loaded_before_mitmcloak_and_the_recorder_last(tmp_path: Path):
    import oby

    command = build_mitmdump_command(
        listen_port=9,
        confdir=tmp_path / "mitm",
        flow_path=tmp_path / "flows.mitm",
        export_dir=tmp_path / "presets",
        catalogue_dir=tmp_path / "seen",
        upstream=None,
    )
    folder = Path(oby.__file__).resolve().parent
    assert command.index(str(folder / "collect.py")) < command.index(cloak_addon_path()) < command.index(str(folder / "record.py"))


def test_recording_report_counts_scripts_and_hides_source(tmp_path: Path, monkeypatch):
    _write(tmp_path / "flows.jsonl", [{"url": "https://example.com/", "response_headers": [["content-type", "text/html"]],
                                       "response_body": {"text": "<script>SECRETSOURCE</script>", "encoding": "utf-8"}}])
    _write(tmp_path / "scripts-parsed.jsonl", [
        {"kind": "inline", "url": "https://example.com/", "source": "SECRETSOURCE", "introduction": ""},
        {"kind": "eval", "url": "", "source": "SECRETSOURCE + 1", "introduction": ""},
    ])
    monkeypatch.setenv("OBY_OUT", str(tmp_path))
    report = recording_report()
    assert report["scripts"] == f"{tmp_path}/scripts.json"
    assert report["scripts_ready"] is False
    assert report["scripts_so_far"] == 2
    assert report["script_kinds"] == {"inline": 1, "eval": 1}
    assert "SECRETSOURCE" not in json.dumps(report)
    assert len(recording.__doc__) < 1024
