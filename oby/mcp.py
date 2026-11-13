"""Hand the recorded browser to invisible-playwright-mcp.

The agent talks to that server. The server launches the patched Firefox.
Traffic goes through the local mitmproxy, so the recording and the TLS mirror
stay in this process.

STEALTHFOX_PROXY is http://127.0.0.1:<port> with no userinfo. The recorder is
open on loopback. An upstream proxy is mitmcloak's, not the browser's.
"""

from __future__ import annotations

import importlib.util
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

from oby.proxy import Mitm, redact_proxy
from oby.session import _now
from oby.trust import write_trust_bundle


def mcp_command() -> list[str]:
    if importlib.util.find_spec("invisible_playwright_mcp") is None:
        raise RuntimeError(
            "invisible-playwright-mcp is not installed in this environment."
        )
    return [sys.executable, "-m", "oby.mcp_entry"]


def mcp_environment(
    *,
    server: str,
    profile: Path,
    trust: Path,
    headless: bool,
) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("STEALTHFOX_NO_PROXY", None)
    # browser_open with no arguments reloads the proxy saved for this session
    # id. The recorder's port is new every launch, so a shared id would send
    # the browser at the previous port. One id per process keeps that file.
    env.update(
        {
            "STEALTHFOX_PROXY": server,
            "STEALTHFOX_PROFILE_DIR": str(profile.resolve()),
            "STEALTHFOX_HEADLESS": "1" if headless else "0",
            "REQUESTS_CA_BUNDLE": str(trust),
            "SSL_CERT_FILE": str(trust),
            "INVISIBLE_MCP_SESSION_ID": f"oby-{os.getpid()}",
            "OBY_OUT": str(profile.parent.resolve()),
        }
    )
    return env


def run_mcp(*, proxy: str | None, out: Path, headless: bool) -> int:
    """Start the recorder, then run invisible-playwright-mcp on the same stdio."""
    from invisible_playwright import ensure_binary

    print("oby: checking the Firefox engine", file=sys.stderr)
    ensure_binary()
    mitm = Mitm(out, upstream=proxy)
    profile = out / "profile"
    profile.mkdir(parents=True, exist_ok=True)
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    print("oby: starting the recorder", file=sys.stderr)
    try:
        server = mitm.start()
    except Exception:
        mitm.stop()
        raise
    trust = write_trust_bundle(mitm.ca_cert, out / "mitm" / "trust.pem")
    command = mcp_command()
    env = mcp_environment(server=server, profile=profile, trust=trust, headless=headless)
    print(
        f"oby: invisible-playwright-mcp via {server} "
        f"(upstream {redact_proxy(proxy) or 'direct'}). "
        f"Close the client to write {os.environ.get('OBY_HOST_OUT') or out}/session.har "
        f"and {os.environ.get('OBY_HOST_OUT') or out}/scripts.json.",
        file=sys.stderr,
    )
    started = _now()
    proc = subprocess.Popen(command, env=env)
    code = 1
    try:
        code = proc.wait()
    except KeyboardInterrupt:
        code = 0
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    finally:
        # The stop can deliver a second signal while the recording is written.
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        mitm.stop()
        _write_har(out, mitm)
        _write_scripts(out, mitm)
        _write_meta(out, mitm, proxy, started)
        label = os.environ.get("OBY_HOST_OUT") or out
        print(f"oby: saved {label}/session.har and {label}/scripts.json", file=sys.stderr)
    return code


def _write_meta(out: Path, mitm: Mitm, proxy: str | None, started: str) -> None:
    count = 0
    if mitm.record_path.exists():
        with mitm.record_path.open(encoding="utf-8") as handle:
            count = sum(1 for line in handle if line.strip())
    meta = {
        "started_at": started,
        "ended_at": _now(),
        "mode": "mcp",
        "browser": "invisible-playwright",
        "upstream_proxy": redact_proxy(proxy),
        "mitm": mitm.server if mitm.port else None,
        "flows": count,
        "files": {
            "har": "session.har",
            "scripts": "scripts.json",
            "flows": "flows.jsonl",
            "script_reports": "scripts-live.jsonl",
            "mitmproxy": "flows.mitm",
            "profile": "profile",
            "presets": "presets",
        },
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")


def _write_har(out: Path, mitm: Mitm) -> None:
    from oby.har import HAR_NAME, write_har

    try:
        write_har(mitm.record_path, out / HAR_NAME)
    except Exception as exc:
        print(f"oby: could not write {HAR_NAME}: {exc}", file=sys.stderr)


def _write_scripts(out: Path, mitm: Mitm) -> None:
    from oby.scripts import write_session_scripts

    write_session_scripts(out, mitm.record_path, mitm.scripts_path)


# Sent once with the browser server's own instructions. The model reads this
# before it calls a tool, so the recording rules live here and on oby_recording.
RECORDING_INSTRUCTIONS = """Oby is recording this browser. The browser talks only to the local recorder on 127.0.0.1. The recorder writes every exchange, and mitmcloak mirrors the browser's TLS toward the site. An upstream proxy, if one was set when Oby started, is used by that recorder. No tool can change it.

Header order, the original casing, and repeated Cookie headers are kept. On HTTP/2 the client's preface, its pseudo-header order and settings, is kept with the exchange.

While you work, exchanges land in flows.jsonl in the output folder. The file to take away is session.har. Oby writes it once, when this client closes. It is a HAR 1.2 log of those exchanges. Headers stay in wire order. Each entry's `_oby` object holds the HTTP/2 preface and the mitmcloak result. The log's `_oby` object points at scripts.json.

scripts.json is written at the same time. It lists the JavaScript that ran. Script files and inline scripts come from the recording. eval, new Function, string timers, and blob workers are reported by a hook that runs before the page's own scripts. The hook sees calls that go through the global eval, Function, setTimeout, setInterval, Worker, and SharedWorker. This Firefox has no script-parsed debugger, so the hook is page JavaScript and a site can see it. The report goes to a name the recorder answers itself, and that exchange is left out of the HAR.

Call oby_recording to read the folder, the HAR path, the scripts path, and how many exchanges and scripts are on disk so far. That tool returns none of the cookies, none of the header values, and none of the script source. session.har and scripts.json contain them. Treat the folder like a password.

Do not start another proxy, and do not browse to the recorder's port. Open the browser with browser_open before any other browser tool, then go where you were asked."""


def recording_report() -> dict:
    """What an agent can know about the capture without reading the secrets in it."""
    out = os.environ.get("OBY_OUT", "")
    shown = os.environ.get("OBY_HOST_OUT") or out
    flows = 0
    jsonl = Path(out) / "flows.jsonl" if out else None
    if jsonl is not None and jsonl.is_file():
        with jsonl.open(encoding="utf-8", errors="replace") as handle:
            flows = sum(1 for line in handle if line.strip())
    ready = bool(out) and (Path(out) / "session.har").is_file()
    folder = shown.rstrip("/")
    root = Path(out) if out else None
    scripts_ready = bool(root) and (root / "scripts.json").is_file()
    counted = {"total": 0, "by_kind": {}}
    if root is not None:
        from oby.scripts import progress

        counted = progress(root / "flows.jsonl", root / "scripts-live.jsonl")
    return {
        "output_dir": shown,
        "har": f"{folder}/session.har" if folder else "session.har",
        "har_ready": ready,
        "scripts": f"{folder}/scripts.json" if folder else "scripts.json",
        "scripts_ready": scripts_ready,
        "flows_so_far": flows,
        "scripts_so_far": counted["total"],
        "script_kinds": counted["by_kind"],
        "written_when": "the MCP client closes",
        "keeps": "header order, repeated cookies, bodies, HTTP/2 preface, mitmcloak result, executed JavaScript",
    }


def recording() -> str:
    """Where this visit is recorded, and when session.har and scripts.json appear.

    Each exchange is written as it finishes. session.har and scripts.json are
    written when the client closes. scripts.json lists the JavaScript that ran:
    network files, inline scripts, eval, new Function, timers, and blob workers.
    This returns the folder, both paths, and the counts. It does not return
    cookies, header values, or script source.
    """
    return json.dumps(recording_report())


def teach(mcp_server) -> None:
    """Tell the browser server that this session ends as a HAR file."""
    current = mcp_server.mcp._mcp_server.instructions or ""
    if "session.har" not in current:
        mcp_server.mcp._mcp_server.instructions = current.rstrip() + "\n\n" + RECORDING_INSTRUCTIONS
    names = {tool.name for tool in mcp_server.mcp._tool_manager.list_tools()}
    if "oby_recording" in names:
        return
    from mcp.types import ToolAnnotations

    mcp_server.mcp.add_tool(
        recording,
        name="oby_recording",
        description=recording.__doc__,
        annotations=ToolAnnotations(
            title="Recording",
            readOnlyHint=True,
            destructiveHint=False,
            openWorldHint=False,
        ),
        structured_output=False,
    )
