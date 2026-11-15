"""One CloakBrowser window, one local mitmproxy, one recording directory."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING
from datetime import datetime, timezone
from pathlib import Path

from oby.proxy import Mitm, redact_proxy
if TYPE_CHECKING:
    from oby.mouse import Pointer


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class Session:
    def __init__(
        self,
        *,
        proxy: str | None = None,
        out: str | Path = "session",
        url: str | None = None,
        headless: bool = False,
        max_body: int | None = None,
        seed: int | None = None,
    ):
        self.upstream = proxy
        self.out = Path(out)
        self.url = url
        self.headless = headless
        self.seed = seed
        self.mitm = Mitm(self.out, upstream=proxy, max_body=max_body)
        self.context = None
        self.page = None
        self.pointer: Pointer | None = None
        self.started_at: str | None = None
        self._closed = False

    def __enter__(self) -> "Session":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> "Session":
        try:
            import os

            from cloakbrowser import ensure_binary

            from oby import chrome

            # Resolve the browser before the recorder, so a machine that
            # cannot run it fails before a proxy is left listening.
            ensure_binary()
            os.environ["OBY_OUT"] = str(self.out.resolve())
            self.started_at = _now()
            self.mitm.start()
            profile = self.out / "chrome-profile"
            profile.mkdir(parents=True, exist_ok=True)
            port = chrome.free_port()
            # humanize stays off. CloakBrowser would curve its own pointer,
            # and Cursory already does that for click and move. One path, not two.
            self.context = chrome.launch(
                profile=profile,
                server=self.mitm.server,
                ca_pem=self.mitm.ca_cert,
                debug_port=port,
                headless=self.headless,
                humanize=False,
            )
            if not chrome.start_watch(port, self.out):
                import sys

                print(
                    "oby: could not attach to Chrome's DevTools port. "
                    "Scripts will be listed from the recording only.",
                    file=sys.stderr,
                )
            self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
            from oby.mouse import Pointer

            self.pointer = Pointer(self.page, seed=self.seed)
            if self.url:
                self.goto(self.url)
        except Exception:
            self.close()
            raise
        return self

    def goto(self, url: str):
        self.url = url
        return self.page.goto(url, wait_until="domcontentloaded", timeout=60_000)

    def click(self, selector: str) -> None:
        self.pointer.click(selector)

    def move(self, x: float, y: float) -> None:
        self.pointer.move(x, y)

    def type_text(self, selector: str, text: str) -> None:
        self.pointer.type_text(selector, text)

    def wait_until_closed(self) -> None:
        import time

        while self._browser_open():
            time.sleep(0.25)

    def _browser_open(self) -> bool:
        try:
            if self.context is None or not self.context.pages:
                return False
            browser = self.context.browser
            if browser is not None and not browser.is_connected():
                return False
            return True
        except Exception:
            return False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Flows are already on disk. Record that before talking to the
        # browser again. A second stop signal during the snapshot used to
        # abandon it; ignore signals until the snapshot and the quit return.
        import signal

        if self.started_at is not None:
            self._write_meta(None)
        # Everything recorded so far is on disk. Write the HAR and the
        # scripts from it now, before asking the browser for anything: the
        # cookie snapshot below can stall, and the session is then stopped
        # from outside. Both files are written again at the end.
        self._save_early()
        previous = (
            (signal.SIGINT, signal.signal(signal.SIGINT, signal.SIG_IGN)),
            (signal.SIGTERM, signal.signal(signal.SIGTERM, signal.SIG_IGN)),
        )
        final_url = None
        try:
            if self.page is not None:
                try:
                    final_url = self.page.url
                except Exception:
                    final_url = None
            if final_url and self.started_at is not None:
                try:
                    self._write_meta(final_url)
                except Exception:
                    pass
            if self.context is not None:
                try:
                    self.context.storage_state(path=str(self.out / "storage.json"))
                except Exception:
                    pass
        finally:
            self.mitm.stop()
            self._write_har()
            self._write_scripts()
            if self.started_at is not None:
                try:
                    self._write_meta(final_url)
                except Exception:
                    pass
            for signum, handler in previous:
                signal.signal(signum, handler)
        if self.context is not None:
            try:
                self.context.close()
            except Exception:
                pass
            self.context = None

    def _write_meta(self, final_url: str | None) -> None:
        count = 0
        path = self.mitm.record_path
        if path.exists():
            with path.open(encoding="utf-8") as handle:
                count = sum(1 for line in handle if line.strip())
        meta = {
            "started_at": self.started_at,
            "ended_at": _now(),
            "browser": "cloakbrowser",
            "final_url": final_url,
            "upstream_proxy": redact_proxy(self.upstream),
            "mitm": self.mitm.server if self.mitm.port else None,
            "flows": count,
            "coverage": _coverage(self.out),
            "files": {
                "har": "session.har",
                "scripts": "scripts.json",
                "flows": "flows.jsonl",
                "websocket": "ws.jsonl",
                "script_files": "scripts",
                "parsed_scripts": "scripts-parsed.jsonl",
                "mitmproxy": "flows.mitm",
                "storage": "storage.json",
                "profile": "chrome-profile",
                "presets": "presets",
            },
        }
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    def _save_early(self) -> None:
        try:
            from oby import query

            query.save(self.out)
        except Exception:
            pass

    def _write_har(self) -> None:
        from oby.har import HAR_NAME, write_har

        try:
            write_har(self.mitm.record_path, self.out / HAR_NAME)
        except Exception as exc:
            import sys

            print(f"oby: could not write {HAR_NAME}: {exc}", file=sys.stderr)

    def _write_scripts(self) -> None:
        from oby.scripts import write_session_scripts

        write_session_scripts(self.out, self.mitm.record_path)


def _coverage(out: Path) -> dict:
    """The browser's own request list against the recording. `missing` should be empty."""
    try:
        from oby import query

        return query.coverage(out)
    except Exception:
        return {}
