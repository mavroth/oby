from __future__ import annotations

import argparse
import os
import signal
import sys
from pathlib import Path


def _proxy(value: str | None) -> str | None:
    return value or os.environ.get("OBY_PROXY") or None


def _build() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--proxy", default=None, help="Upstream proxy. Defaults to OBY_PROXY.")
    common.add_argument("--out", default="session", help="Directory the recording is written to")
    common.add_argument(
        "--fingerprints",
        action="store_true",
        help="Also record which fingerprinting APIs each page calls. This runs a script in the page, "
        "which a site can detect. Defaults to OBY_FINGERPRINTS=1.",
    )

    parser = argparse.ArgumentParser(
        prog="oby",
        description="Record a stealth browser session as a HAR, including the JavaScript that ran.",
    )
    sub = parser.add_subparsers(dest="cmd")

    browse = sub.add_parser(
        "browse",
        parents=[common],
        help="Open a window you drive yourself",
        description="Open the browser and record the visit. session.har and scripts.json are written when the window closes.",
    )
    browse.add_argument("--url", default=None)
    browse.add_argument("--headless", action="store_true")

    agent = sub.add_parser(
        "mcp",
        parents=[common],
        help="Let an agent drive the browser",
        description="Start the same recorder and let an agent drive the browser. session.har and scripts.json are written when the client closes.",
    )
    agent.add_argument("--headless", action="store_true", help="Hide the window. Default is visible.")

    readable = sub.add_parser(
        "deobfuscate",
        help="Write a readable copy of each recorded script",
        description="Write scripts/<sha256>.deob.js for the scripts of a recording: reformatted, with escaped strings, "
        "hex numbers, and bracket property names spelled plainly. The originals are kept. Nothing is executed.",
    )
    readable.add_argument("--out", default="session", help="The recording folder")
    readable.add_argument("sha256", nargs="*", help="Scripts to do, by sha256 or a prefix. Default is all of them.")
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # `oby --help` is the program. A flag after that still means browse.
    if raw in (["-h"], ["--help"]):
        _build().parse_args(raw)
    if not raw or raw[0].startswith("-"):
        raw = ["browse", *raw]
    args = _build().parse_args(raw)
    proxy = _proxy(getattr(args, "proxy", None))
    if args.cmd == "deobfuscate":
        return _deobfuscate(Path(args.out), args.sha256)
    fingerprints = args.fingerprints or os.environ.get("OBY_FINGERPRINTS") == "1"
    if args.cmd == "mcp":
        return _mcp(proxy, Path(args.out), args.headless, fingerprints)
    return _browse(proxy, Path(args.out), args.url, args.headless, fingerprints)


def _save_on_term() -> None:
    # A client closing its server, or a service manager, delivers SIGTERM.
    # Python would die before close() wrote the recording. Treat it like Ctrl+C.
    signal.signal(signal.SIGTERM, _raise_interrupt)


def _raise_interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def _browse(proxy: str | None, out: Path, url: str | None, headless: bool, fingerprints: bool = False) -> int:
    from oby.session import Session

    _save_on_term()
    label = out
    print(f"Recording into {label}", flush=True)
    if proxy:
        print("Upstream proxy is set. The browser itself talks only to the local recorder.")
    try:
        with Session(proxy=proxy, out=out, headless=headless, fingerprints=fingerprints) as session:
            print("Close the browser window, or press Ctrl+C, to save.", flush=True)
            if url:
                try:
                    session.goto(url)
                except Exception as exc:
                    print(f"Could not open {url}: {exc}", file=sys.stderr)
            session.wait_until_closed()
    except KeyboardInterrupt:
        print("\nSaving.", flush=True)
    except Exception as exc:
        print(f"oby: {exc}", file=sys.stderr)
        return 1
    print(f"Saved {label}/session.har and {label}/scripts.json", flush=True)
    return 0


def _deobfuscate(out: Path, wanted: list[str]) -> int:
    from oby import deob, query
    from oby.scripts import SCRIPTS_DIR

    items = [item for item in query._script_items(out) if isinstance(item.get("source"), str)]
    if wanted:
        items = [item for item in items if any(item["sha256"].startswith(prefix.lower()) for prefix in wanted)]
    if not items:
        print(f"oby: no scripts to do in {out}", file=sys.stderr)
        return 1
    done: set[str] = set()
    for item in items:
        if item["sha256"] in done:
            continue
        done.add(item["sha256"])
        try:
            _text, how = deob.view(out / SCRIPTS_DIR, item["sha256"], item["source"], "deobfuscated")
        except Exception as exc:
            print(f"oby: {item['sha256'][:12]} failed: {exc}", file=sys.stderr)
            continue
        print(f"{how.get('file', '')}  {item.get('kind')}  {str(item.get('url') or '')[:80]}", flush=True)
    return 0


def _mcp(proxy: str | None, out: Path, headless: bool, fingerprints: bool = False) -> int:
    from oby.mcp import run_mcp

    _save_on_term()
    try:
        return run_mcp(proxy=proxy, out=out, headless=headless, fingerprints=fingerprints)
    except Exception as exc:
        print(f"oby: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
