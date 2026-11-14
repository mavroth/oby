"""One invisible-playwright window, one local mitmproxy, one recording directory."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from oby.mouse import Pointer
from oby.proxy import Mitm, redact_proxy
from oby.trust import (
    accept_recorder_certificate,
    browser_proxy,
    restore_trust,
    use_trust_bundle,
    write_trust_bundle,
)


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
        max_body: int = 1_000_000,
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
        self._launcher = None
        self._saved_trust: dict[str, str | None] | None = None

    def __enter__(self) -> "Session":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> "Session":
        try:
            # Resolve the engine before the recorder, so a machine with no
            # published binary fails before a proxy is left listening.
            from invisible_playwright import InvisiblePlaywright, ensure_binary

            from oby.parsed import prepare_output

            prepare_output(self.out)
            ensure_binary()
            self.started_at = _now()
            self.mitm.start()
            bundle = write_trust_bundle(self.mitm.ca_cert, self.out / "mitm" / "trust.pem")
            self._saved_trust = use_trust_bundle(bundle)
            accept_recorder_certificate()
            profile = self.out / "profile"
            profile.mkdir(parents=True, exist_ok=True)
            # humanize stays off. This browser curves its own pointer, and
            # Cursory already does that for click and move. One path, not two.
            # The proxy dict is the browser's own proxy setting.
            self._launcher = InvisiblePlaywright(
                headless=self.headless,
                proxy=browser_proxy(self.mitm.server),
                profile_dir=profile,
                seed=self.seed,
                humanize=False,
            )
            self.context = self._launcher.__enter__()
            self.page = self.context.pages[0] if self.context.pages else self.context.new_page()
            self.pointer = Pointer(self.page, seed=self.seed)
            if self.url:
                self.goto(self.url)
        except Exception:
            self.close()
            raise
        return self

    def goto(self, url: str):
        # page.goto waits until the debugger is listening, then sends this
        # document. Waiting here as well kept the request off the recorder.
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

        # The container asks us to save by creating this file, instead of
        # with a signal. A signal in the middle of the driver call makes the
        # cookie snapshot wait forever.
        stop_file = Path("/tmp/oby-stop")
        while not stop_file.exists() and self._browser_open():
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
            restore_trust(self._saved_trust)
            self._saved_trust = None
            for signum, handler in previous:
                signal.signal(signum, handler)
        if self._launcher is not None:
            try:
                self._launcher.__exit__(None, None, None)
            except Exception:
                pass
            self._launcher = None

    def _write_meta(self, final_url: str | None) -> None:
        count = 0
        path = self.mitm.record_path
        if path.exists():
            with path.open(encoding="utf-8") as handle:
                count = sum(1 for line in handle if line.strip())
        meta = {
            "started_at": self.started_at,
            "ended_at": _now(),
            "browser": "invisible-playwright",
            "final_url": final_url,
            "upstream_proxy": redact_proxy(self.upstream),
            "mitm": self.mitm.server if self.mitm.port else None,
            "flows": count,
            "files": {
                "har": "session.har",
                "scripts": "scripts.json",
                "flows": "flows.jsonl",
                "script_reports": "scripts-live.jsonl",
                "parsed_scripts": "scripts-parsed.jsonl",
                "mitmproxy": "flows.mitm",
                "storage": "storage.json",
                "profile": "profile",
                "presets": "presets",
            },
        }
        self.out.mkdir(parents=True, exist_ok=True)
        (self.out / "meta.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")

    def _write_har(self) -> None:
        from oby.har import HAR_NAME, write_har

        try:
            write_har(self.mitm.record_path, self.out / HAR_NAME)
        except Exception as exc:
            import sys

            print(f"oby: could not write {HAR_NAME}: {exc}", file=sys.stderr)

    def _write_scripts(self) -> None:
        from oby.scripts import write_session_scripts

        write_session_scripts(self.out, self.mitm.record_path, self.mitm.scripts_path)
