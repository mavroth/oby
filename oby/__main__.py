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
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    # `oby --help` is the program. A flag after that still means browse.
    if raw in (["-h"], ["--help"]):
        _build().parse_args(raw)
    if not raw or raw[0].startswith("-"):
        raw = ["browse", *raw]
    args = _build().parse_args(raw)
    proxy = _proxy(args.proxy)
    if args.cmd == "mcp":
        return _mcp(proxy, Path(args.out), args.headless)
    return _browse(proxy, Path(args.out), args.url, args.headless)


def _save_on_term() -> None:
    # A client closing its server, or a service manager, delivers SIGTERM.
    # Python would die before close() wrote the recording. Treat it like Ctrl+C.
    signal.signal(signal.SIGTERM, _raise_interrupt)


def _raise_interrupt(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def _browse(proxy: str | None, out: Path, url: str | None, headless: bool) -> int:
    from oby.session import Session

    _save_on_term()
    label = out
    print(f"Recording into {label}", flush=True)
    if proxy:
        print("Upstream proxy is set. The browser itself talks only to the local recorder.")
    try:
        with Session(proxy=proxy, out=out, headless=headless) as session:
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


def _mcp(proxy: str | None, out: Path, headless: bool) -> int:
    from oby.mcp import run_mcp

    _save_on_term()
    try:
        return run_mcp(proxy=proxy, out=out, headless=headless)
    except Exception as exc:
        print(f"oby: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
