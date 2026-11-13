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
        "Close the client to save.",
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
        _write_meta(out, mitm, proxy, started)
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
            "flows": "flows.jsonl",
            "mitmproxy": "flows.mitm",
            "profile": "profile",
            "presets": "presets",
        },
    }
    out.mkdir(parents=True, exist_ok=True)
    (out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
