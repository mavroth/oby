"""Let an agent drive the recorded browser.

One process: the recorder, CloakBrowser, the DevTools watch, and the MCP
server on this stdio. The server answers at once. The recorder starts
beside it, and a tool call waits until the recorder is listening.

The browser tools are Playwright's, on the browser CloakBrowser opened, so
clicks and typing are the human-shaped ones that library makes. A snapshot
gives each element a ref, and click and type take that ref.
"""

from __future__ import annotations

import asyncio
import json
import os
import signal
import sys
import threading
import time
from pathlib import Path

from oby.proxy import Mitm, redact_proxy

READY_WAIT = 60.0
NAV_TIMEOUT = 60_000
ACTION_TIMEOUT = 15_000

INSTRUCTIONS = """Oby is recording this browser. It is CloakBrowser, a patched Chromium, running on this machine. The browser talks only to the local recorder on 127.0.0.1. The recorder writes every exchange, and mitmcloak mirrors the browser's TLS toward the site. An upstream proxy, if one was set when Oby started, is used by that recorder. No tool can change it.

Open the browser with browser_open, then browser_navigate. browser_snapshot returns the page as a tree in which each element has a ref such as e12. Pass that ref to browser_click, browser_type, and browser_select_option. Take a new snapshot after the page changes, because refs belong to the snapshot that gave them.

Header order, the original casing, and repeated Cookie headers are kept. On HTTP/2 the client's preface, its pseudo-header order and settings, is kept with the exchange. Bodies are kept whole. A response is passed to the page as it arrives. WebSocket messages are recorded with their handshake exchange, and a text/event-stream body is also split into its events, each with its arrival time.

While you work, exchanges land in flows.jsonl in the output folder. Each launch moves the previous visit's files into history/ in that folder. The profile stays. The file to take away is session.har, a HAR 1.2 log of those exchanges, written when this client closes or when you call oby_save. Each entry's `_oby` object holds the HTTP/2 preface, the timings, and the script frame that made the request.

scripts.json is written at the same time. It lists the JavaScript Chrome parsed: fetched files, inline scripts, eval, new Function, string timers, blob workers, and workers. A DevTools client on loopback reads them from the engine. Nothing is injected into the page for the recording.

Call oby_recording for the folder, both paths, and the counts so far. It returns none of the cookies, header values, or script source. `requests_not_recorded` should be 0: it counts requests the browser got an answer to that the recorder has no exchange for.

You can read the recording while the visit is running. oby_exchanges lists what was sent, filters by host, method, status, or text, and names the script frame that made each request. oby_exchange returns one exchange with its headers and bodies. oby_messages returns the WebSocket messages of a handshake exchange. oby_scripts lists the scripts and finds text in their source. oby_script returns a slice of one script. These return what the site and the browser sent, cookies and tokens included, so read only what the task needs and do not repeat secrets to the person. Treat the folder like a password.

Do not start another proxy, and do not browse to the recorder's port."""


class Browser:
    """The one browser of this server, opened on first use."""

    def __init__(self, out: Path, mitm: Mitm, headless: bool):
        self.out = out
        self.mitm = mitm
        self.headless = headless
        self.context = None
        self.page = None
        self.ready = threading.Event()
        self.failure: str | None = None
        self._lock = asyncio.Lock()

    async def wait_ready(self) -> None:
        deadline = time.monotonic() + READY_WAIT
        while not self.ready.is_set():
            if self.failure:
                raise RuntimeError(self.failure)
            if time.monotonic() > deadline:
                raise RuntimeError("the oby recorder did not start. See mitmdump.log in the output folder.")
            await asyncio.sleep(0.05)
        if self.failure:
            raise RuntimeError(self.failure)

    async def open(self):
        """The current page, launching the browser if it is not open."""
        await self.wait_ready()
        async with self._lock:
            if self.context is None:
                from oby import chrome, storage

                profile = self.out / "chrome-profile"
                profile.mkdir(parents=True, exist_ok=True)
                port = chrome.free_port()
                self.context = await chrome.launch_async(
                    profile=profile,
                    server=self.mitm.server,
                    ca_pem=self.mitm.ca_cert,
                    debug_port=port,
                    headless=self.headless,
                    humanize=True,
                )
                storage.remember(self.context)
                attached = await asyncio.to_thread(chrome.start_watch, port, self.out)
                if not attached:
                    print("oby: could not attach to Chrome's DevTools port.", file=sys.stderr)
                self.context.on("page", self._adopt)
                self.context.set_default_timeout(ACTION_TIMEOUT)
                self.context.set_default_navigation_timeout(NAV_TIMEOUT)
                pages = self.context.pages
                self.page = pages[0] if pages else await self.context.new_page()
            if self.page is None or self.page.is_closed():
                pages = [page for page in self.context.pages if not page.is_closed()]
                self.page = pages[-1] if pages else await self.context.new_page()
            return self.page

    def _adopt(self, page) -> None:
        # A link that opens a tab moves the agent to it, as it would a person.
        self.page = page

    async def close(self) -> None:
        from oby import chrome, storage

        context, self.context, self.page = self.context, None, None
        if context is None:
            return
        try:
            await storage.save_async(self.out)
        except Exception:
            pass
        await asyncio.to_thread(chrome.stop_watch)
        storage.forget(context)
        try:
            await context.close()
        except Exception:
            pass


async def _target(page, ref: str | None, selector: str | None):
    """The element to act on, from a snapshot ref or a CSS selector.

    A ref is turned into the element itself first. CloakBrowser's
    human-shaped click and typing look an element up by selector, and they
    do not know the snapshot's refs.
    """
    if ref:
        return await page.locator(f"aria-ref={ref.strip()}").element_handle(timeout=ACTION_TIMEOUT)
    if selector:
        return page.locator(selector).first
    raise ValueError("give a ref from browser_snapshot, or a selector")


async def _state(page) -> str:
    try:
        title = await page.title()
    except Exception:
        title = ""
    return json.dumps({"url": page.url, "title": title})


def build_server(browser: Browser):
    from mcp.server.fastmcp import FastMCP, Image
    from mcp.types import ToolAnnotations

    server = FastMCP("oby", instructions=INSTRUCTIONS)

    def tool(title: str, *, read_only: bool = False):
        return server.tool(
            annotations=ToolAnnotations(title=title, readOnlyHint=read_only, destructiveHint=False, openWorldHint=True),
            structured_output=False,
        )

    @tool("Open the browser")
    async def browser_open(url: str | None = None) -> str:
        """Open the recorded browser, and go to `url` if one is given. Call this first."""
        page = await browser.open()
        if url:
            await page.goto(url, wait_until="domcontentloaded")
        return await _state(page)

    @tool("Go to a URL")
    async def browser_navigate(url: str) -> str:
        """Load `url` in the current tab and wait for the document. Returns the final URL and title."""
        page = await browser.open()
        await page.goto(url, wait_until="domcontentloaded")
        return await _state(page)

    @tool("Go back")
    async def browser_back() -> str:
        """Go back one page in the current tab's history."""
        page = await browser.open()
        await page.go_back(wait_until="domcontentloaded")
        return await _state(page)

    @tool("Page snapshot", read_only=True)
    async def browser_snapshot() -> str:
        """The page as an accessibility tree. Each element has a ref, such as e12, for browser_click and browser_type."""
        page = await browser.open()
        tree = await page.aria_snapshot(mode="ai")
        return f"url: {page.url}\ntitle: {await page.title()}\n\n{tree}"

    @tool("Page text", read_only=True)
    async def browser_read_text(max_chars: int = 50_000) -> str:
        """The visible text of the page, up to `max_chars` characters."""
        page = await browser.open()
        text = await page.inner_text("body")
        return text[:max_chars]

    @tool("Page HTML", read_only=True)
    async def browser_read_html(selector: str | None = None, max_chars: int = 100_000) -> str:
        """The HTML of the page as it is now, or of the first element matching `selector`."""
        page = await browser.open()
        html = await page.locator(selector).first.evaluate("e => e.outerHTML") if selector else await page.content()
        return html[:max_chars]

    @tool("Screenshot", read_only=True)
    async def browser_take_screenshot(full_page: bool = False):
        """A PNG of the viewport, or of the whole page. Also saved in the output folder under artifacts/."""
        page = await browser.open()
        data = await page.screenshot(full_page=full_page, type="png")
        folder = browser.out / "artifacts"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / f"screenshot-{int(time.time() * 1000)}.png").write_bytes(data)
        return Image(data=data, format="png")

    @tool("Click")
    async def browser_click(ref: str | None = None, selector: str | None = None, double: bool = False) -> str:
        """Click an element, by its ref from browser_snapshot or by a CSS selector."""
        page = await browser.open()
        target = await _target(page, ref, selector)
        await (target.dblclick() if double else target.click())
        return await _state(browser.page or page)

    @tool("Click at a point")
    async def browser_click_at(x: float, y: float) -> str:
        """Click at viewport coordinates, for a canvas or anything a snapshot does not name."""
        page = await browser.open()
        await page.mouse.click(x, y)
        return await _state(browser.page or page)

    @tool("Type")
    async def browser_type(text: str, ref: str | None = None, selector: str | None = None, clear: bool = True, submit: bool = False) -> str:
        """Type `text` into a field, key by key. `clear` empties it first. `submit` presses Enter after."""
        page = await browser.open()
        target = await _target(page, ref, selector)
        await target.click()
        # Typed at the keyboard, into whatever the click focused. A page
        # often swaps the field for another one as it takes focus.
        if clear:
            await page.keyboard.press("ControlOrMeta+A")
            await page.keyboard.press("Backspace")
        await page.keyboard.type(text)
        if submit:
            await page.keyboard.press("Enter")
        return await _state(browser.page or page)

    @tool("Press a key")
    async def browser_press_key(key: str) -> str:
        """Press a key or chord on the page, such as Enter, Escape, ArrowDown, or Control+A."""
        page = await browser.open()
        await page.keyboard.press(key)
        return await _state(browser.page or page)

    @tool("Choose an option")
    async def browser_select_option(values: list[str], ref: str | None = None, selector: str | None = None) -> str:
        """Choose options in a select element, by value or by label."""
        page = await browser.open()
        chosen = await (await _target(page, ref, selector)).select_option(values)
        return json.dumps({"selected": chosen})

    @tool("Upload files")
    async def browser_upload_files(paths: list[str], ref: str | None = None, selector: str | None = None) -> str:
        """Set the files of a file input."""
        page = await browser.open()
        await (await _target(page, ref, selector)).set_input_files(paths)
        return json.dumps({"uploaded": len(paths)})

    @tool("Run JavaScript")
    async def browser_evaluate(expression: str) -> str:
        """Evaluate a JavaScript expression in the page and return its JSON value. The page can see what it changes."""
        from oby import chrome

        page = await browser.open()
        # The agent's own code is not the site's, so it is kept out of scripts.json.
        chrome.ignore_source(expression)
        return json.dumps(await page.evaluate(expression), default=str)

    @tool("Wait", read_only=True)
    async def browser_wait(seconds: float = 0, text: str | None = None, gone: str | None = None) -> str:
        """Wait for `text` to appear, for `gone` to disappear, or for `seconds` (at most 60)."""
        page = await browser.open()
        if text:
            await page.get_by_text(text).first.wait_for(state="visible", timeout=NAV_TIMEOUT)
        if gone:
            await page.get_by_text(gone).first.wait_for(state="hidden", timeout=NAV_TIMEOUT)
        if seconds:
            await asyncio.sleep(min(max(seconds, 0), 60))
        return await _state(page)

    @tool("Tabs")
    async def browser_tabs(action: str = "list", index: int | None = None, url: str | None = None) -> str:
        """List the open tabs, or `select`, `close`, or open a `new` one. `index` is the tab's place in the list."""
        page = await browser.open()
        pages = [item for item in browser.context.pages if not item.is_closed()]
        if action == "new":
            page = await browser.context.new_page()
            if url:
                await page.goto(url, wait_until="domcontentloaded")
            browser.page = page
        elif action in ("select", "close"):
            if index is None or not 0 <= index < len(pages):
                raise ValueError(f"index is 0 to {len(pages) - 1}")
            if action == "select":
                browser.page = pages[index]
                await browser.page.bring_to_front()
            else:
                await pages[index].close()
                await browser.open()
        elif action != "list":
            raise ValueError("action is list, new, select, or close")
        pages = [item for item in browser.context.pages if not item.is_closed()]
        return json.dumps(
            [{"index": number, "url": item.url, "current": item is browser.page} for number, item in enumerate(pages)]
        )

    @tool("Close the browser")
    async def browser_close() -> str:
        """Close the browser. The recording stays, and session.har is written when this client closes."""
        await browser.close()
        return json.dumps({"closed": True})

    _add_recording_tools(server)
    return server


def _add_recording_tools(server) -> None:
    from mcp.types import ToolAnnotations

    for name, function, title, read_only in (*_TOOLS, ("oby_recording", recording, "Recording", True)):
        server.add_tool(
            function,
            name=name,
            description=function.__doc__,
            annotations=ToolAnnotations(
                title=title, readOnlyHint=read_only, destructiveHint=False, idempotentHint=True, openWorldHint=False
            ),
            structured_output=False,
        )


def recording_report() -> dict:
    """What an agent can know about the capture without reading the secrets in it."""
    out = os.environ.get("OBY_OUT", "")
    shown = out
    flows = 0
    jsonl = Path(out) / "flows.jsonl" if out else None
    if jsonl is not None and jsonl.is_file():
        with jsonl.open(encoding="utf-8", errors="replace") as handle:
            flows = sum(1 for line in handle if line.strip())
    ready = bool(out) and (Path(out) / "session.har").is_file()
    messages = 0
    sockets = Path(out) / "ws.jsonl" if out else None
    if sockets is not None and sockets.is_file():
        with sockets.open(encoding="utf-8", errors="replace") as handle:
            messages = sum(1 for line in handle if line.strip() and '"closed": true' not in line)
    folder = shown.rstrip("/")
    root = Path(out) if out else None
    scripts_ready = bool(root) and (root / "scripts.json").is_file()
    counted = {"total": 0, "by_kind": {}}
    covered = {"browser_reported": 0, "missing": [], "from_cache": 0, "unanswered": []}
    if root is not None:
        from oby import query

        try:
            covered = query.coverage(root)
        except Exception:
            pass
        from oby.scripts import PARSED_NAME, progress

        counted = progress(root / "flows.jsonl", root / PARSED_NAME)
    return {
        "output_dir": shown,
        "har": f"{folder}/session.har" if folder else "session.har",
        "har_ready": ready,
        "scripts": f"{folder}/scripts.json" if folder else "scripts.json",
        "scripts_ready": scripts_ready,
        "flows_so_far": flows,
        "websocket_messages_so_far": messages,
        "requests_browser_reported": covered["browser_reported"],
        "requests_not_recorded": len(covered["missing"]),
        "requests_answered_from_cache": covered["from_cache"],
        "requests_never_answered": len(covered["unanswered"]),
        "scripts_so_far": counted["total"],
        "script_kinds": counted["by_kind"],
        "written_when": "the MCP client closes, or when oby_save is called",
        "keeps": "header order, repeated cookies, whole bodies, WebSocket messages, timings, HTTP/2 preface, mitmcloak result, executed JavaScript",
    }


def recording() -> str:
    """Where this visit is recorded, and when session.har and scripts.json appear.

    Each exchange is written as it finishes. session.har and scripts.json
    are written when the client closes, or when oby_save is called.
    scripts.json lists the JavaScript Chrome parsed: files, inline scripts,
    eval, new Function, timers, blob workers, and workers. This returns the
    folder, both paths, and the counts. `requests_not_recorded` should be 0.
    It does not return cookies, header values, or script source.
    """
    return json.dumps(recording_report())


def _out() -> Path:
    return Path(os.environ.get("OBY_OUT") or ".")


def _reply(build) -> str:
    try:
        return json.dumps(build(), default=str)
    except Exception as exc:
        return json.dumps({"error": f"{exc.__class__.__name__}: {exc}"})


def exchanges(
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
    contains: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> str:
    """List the exchanges recorded so far, oldest first, without their bodies.

    Each row has an index, the method, URL, status, content type, and body
    sizes. `initiator` is the script frame that made the request, as
    file:line:column and the function name. `host` matches part of the hostname. `contains` matches text in
    the URL, the headers, or either body. Use the index with oby_exchange,
    or with oby_messages when the row counts WebSocket messages.
    """
    from oby import query

    return _reply(
        lambda: query.exchanges(
            _out(), host=host, method=method, status=status, contains=contains, offset=offset, limit=limit
        )
    )


def exchange(index: int, max_body: int = 20_000) -> str:
    """Return one recorded exchange: headers in wire order, both bodies, timing, and the HTTP/2 preface.

    A body longer than `max_body` characters is clipped here and its full
    length is given. The whole body is in flows.jsonl and session.har. This
    returns real cookies and tokens.
    """
    from oby import query

    return _reply(lambda: query.exchange(_out(), index, max_body=max_body))


def messages(index: int, offset: int = 0, limit: int = 100) -> str:
    """Return the WebSocket messages of the handshake exchange at `index`, oldest first.

    Each message has its direction, time, size, and text. A binary message is
    base64. The reply also says how the socket closed, once it has.
    """
    from oby import query

    return _reply(lambda: query.messages(_out(), index, offset=offset, limit=limit))


def scripts(
    contains: str | None = None,
    kind: str | None = None,
    url: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> str:
    """List the JavaScript recorded so far, without the source.

    Each row has the sha256, kind (network, inline, eval, function, timer,
    blob), URL, and length. `contains` keeps the scripts whose source has
    that text and shows up to three places it occurs, with their offsets.
    Use the sha256 with oby_script.
    """
    from oby import query

    return _reply(
        lambda: query.scripts(_out(), contains=contains, kind=kind, url=url, offset=offset, limit=limit)
    )


def script(sha256: str, offset: int = 0, length: int = 20_000) -> str:
    """Return `length` characters of one script's source, starting at `offset`.

    `sha256` comes from oby_scripts. The first characters of it are enough
    when they are unique. The reply gives the script's full length.
    """
    from oby import query

    return _reply(lambda: query.script(_out(), sha256, offset=offset, length=length))


async def save() -> str:
    """Write session.har, scripts.json, scripts/, and storage.json now, from what is recorded so far.

    The visit keeps recording. The same files are written again when the
    client closes. Returns the counts and none of the content.
    """
    from oby import query, storage

    def build() -> dict:
        return query.save(_out())

    try:
        result = build()
    except Exception as exc:
        return json.dumps({"error": f"{exc.__class__.__name__}: {exc}"})
    try:
        result["storage"] = await storage.save_async(_out())
    except Exception:
        result["storage"] = None
    shown = str(_out()).rstrip("/")
    result["output_dir"] = shown
    return json.dumps(result)


# name, function, title, and whether the tool only reads.
_TOOLS = (
    ("oby_exchanges", exchanges, "Recorded exchanges", True),
    ("oby_exchange", exchange, "One recorded exchange", True),
    ("oby_messages", messages, "WebSocket messages", True),
    ("oby_scripts", scripts, "Recorded scripts", True),
    ("oby_script", script, "One recorded script", True),
    ("oby_save", save, "Write the recording now", False),
)


def _write_meta(out: Path, mitm: Mitm, proxy: str | None, started: str) -> None:
    count = 0
    if mitm.record_path.exists():
        with mitm.record_path.open(encoding="utf-8") as handle:
            count = sum(1 for line in handle if line.strip())
    meta = {
        "started_at": started,
        "ended_at": _now(),
        "mode": "mcp",
        "browser": "cloakbrowser",
        "upstream_proxy": redact_proxy(proxy),
        "mitm": mitm.server if mitm.port else None,
        "flows": count,
        "coverage": _coverage(out),
        "files": {
            "har": "session.har",
            "scripts": "scripts.json",
            "flows": "flows.jsonl",
            "websocket": "ws.jsonl",
            "script_files": "scripts",
            "storage": "storage.json",
            "initiators": "initiators.jsonl",
            "parsed_scripts": "scripts-parsed.jsonl",
            "mitmproxy": "flows.mitm",
            "profile": "chrome-profile",
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

    write_session_scripts(out, mitm.record_path)


def _coverage(out: Path) -> dict:
    """The browser's own request list against the recording. `missing` should be empty."""
    try:
        from oby import query

        return query.coverage(out)
    except Exception:
        return {}


def run_mcp(*, proxy: str | None, out: Path, headless: bool) -> int:
    from oby.session import _now

    # The recording tools read the folder from here.
    os.environ["OBY_OUT"] = str(Path(out).resolve())
    mitm = Mitm(out, upstream=proxy)
    mitm.prepare()
    (out / "artifacts").mkdir(parents=True, exist_ok=True)
    browser = Browser(out, mitm, headless)
    started = _now()

    def start_recorder() -> None:
        try:
            from cloakbrowser import ensure_binary

            mitm.start()
            ensure_binary()
        except Exception as exc:
            browser.failure = f"the oby recorder did not start: {exc}"
        finally:
            browser.ready.set()

    threading.Thread(target=start_recorder, name="oby-recorder", daemon=True).start()
    label = out
    print(
        f"oby: recording Chrome via {mitm.server} (upstream {redact_proxy(proxy) or 'direct'}). "
        f"Close the client to write {label}/session.har and {label}/scripts.json.",
        file=sys.stderr,
    )
    import logging

    # The server logs every request to stderr, which a client shows as noise.
    logging.getLogger("mcp").setLevel(logging.WARNING)
    logging.getLogger("httpx").setLevel(logging.WARNING)
    server = build_server(browser)

    async def serve() -> None:
        try:
            await server.run_stdio_async()
        finally:
            # The client is gone. Finish the browser's part even if this
            # task is being cancelled by the signal that ended it.
            await asyncio.shield(browser.close())

    code = 0
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    except Exception as exc:
        print(f"oby: {exc}", file=sys.stderr)
        code = 1
    finally:
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        browser.ready.wait(5)
        mitm.stop()
        _write_har(out, mitm)
        _write_scripts(out, mitm)
        _write_meta(out, mitm, proxy, started)
        print(f"oby: saved {label}/session.har and {label}/scripts.json", file=sys.stderr)
    return code
