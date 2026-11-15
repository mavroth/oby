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

Open the browser with browser_open, then browser_navigate. Every tool that changes the page returns the page as it is afterwards: a tree in which each element has a ref such as e12. Pass that ref to browser_click, browser_type, browser_select_option, browser_hover, and browser_upload_files. Use the refs from the latest result. A large page is returned as its controls only, and browser_snapshot gives the whole tree.

browser_type sets any field the right way: it types into text fields and rich-text editors, sets a date, time, colour, or slider to the value given, chooses a dropdown option by its label, and takes true or false for a checkbox. browser_fill_form does several fields in one call. Elements inside iframes and shadow DOM have refs like any other. An alert, confirm, or prompt is answered for you (accepted, unless browser_handle_dialog said otherwise) and reported in the next result.

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
        # What happened on the page since the last tool result: dialogs and new tabs.
        self.events: list[dict] = []
        self.accept_dialogs = True
        self.dialog_text: str | None = None

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
                for page in self.context.pages:
                    self._watch(page)
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
        self._watch(page)
        self.events.append({"new_tab": "the page opened a new tab, and it is now the current one"})

    def _watch(self, page) -> None:
        if getattr(page, "_oby_watched", False):
            return
        page._oby_watched = True
        page.on("dialog", lambda dialog: asyncio.ensure_future(self._dialog(dialog)))

    async def _dialog(self, dialog) -> None:
        """Answer an alert, confirm, or prompt, so the page is never left blocked."""
        seen = {"dialog": dialog.type, "message": dialog.message, "answer": "accepted" if self.accept_dialogs else "dismissed"}
        try:
            if self.accept_dialogs:
                await dialog.accept(self.dialog_text or dialog.default_value or "")
            else:
                await dialog.dismiss()
        except Exception:
            seen["answer"] = "already closed"
        self.events.append(seen)

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


SNAPSHOT_INLINE = 20_000
# Inputs a person sets with a picker. Typing digits into one gives a wrong value.
_PICKERS = frozenset({"date", "time", "datetime-local", "month", "week", "color"})
_YES = frozenset({"true", "on", "yes", "1", "checked"})
_NO = frozenset({"false", "off", "no", "0", "unchecked"})
_INTERACTIVE = frozenset({
    "button", "link", "textbox", "searchbox", "checkbox", "radio", "combobox", "listbox", "option", "slider",
    "spinbutton", "switch", "tab", "menuitem", "menuitemcheckbox", "menuitemradio", "treeitem", "heading", "iframe",
})
_DESCRIBE = """e => ({
  tag: e.tagName.toLowerCase(),
  type: (e.getAttribute('type') || '').toLowerCase(),
  disabled: !!e.disabled,
  checked: !!e.checked,
})"""
_SET_VALUE = """(e, value) => {
  const proto = e instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(e, value);
  e.dispatchEvent(new Event('input', {bubbles: true}));
  e.dispatchEvent(new Event('change', {bubbles: true}));
}"""
_BRING_NEAR = """e => {
  const box = e.getBoundingClientRect();
  const tall = window.innerHeight;
  if (box.bottom < -tall || box.top > 2 * tall) e.scrollIntoView({block: 'center', inline: 'center'});
}"""
_PICK_OPTION = """e => {
  const select = e.closest('select');
  if (!select) return false;
  e.selected = select.multiple ? !e.selected : true;
  select.dispatchEvent(new Event('input', {bubbles: true}));
  select.dispatchEvent(new Event('change', {bubbles: true}));
  return true;
}"""


async def _target(page, ref: str | None, selector: str | None):
    """The element to act on, from a snapshot ref or a CSS selector.

    Always the element itself. CloakBrowser's human-shaped click and typing
    look an element up by selector, and they do not know the snapshot's refs.
    """
    if not ref and not selector:
        raise ValueError("give a ref from the latest snapshot, or a selector")
    locator = page.locator(f"aria-ref={ref.strip()}") if ref else page.locator(selector).first
    try:
        handle = await locator.element_handle(timeout=2_000 if ref else ACTION_TIMEOUT)
    except Exception as exc:
        if ref:
            raise ValueError(
                f"no element has ref {ref} now. Refs belong to the latest snapshot. Call browser_snapshot and use the new ref."
            ) from exc
        raise ValueError(f"nothing on the page matches the selector {selector!r}") from exc
    if handle is None:
        raise ValueError("that element is not on the page any more. Call browser_snapshot.")
    return handle


async def _point(handle) -> tuple[float, float]:
    await handle.evaluate("e => e.scrollIntoView({block: 'center', inline: 'center'})")
    box = await handle.bounding_box()
    if not box:
        raise ValueError("that element is not visible, so the pointer cannot reach it")
    return box["x"] + box["width"] / 2, box["y"] + box["height"] / 2


async def _click(page, handle, *, double: bool = False) -> None:
    """Click an element the way a person would, wherever it lives.

    The human-shaped click cannot follow an element inside an iframe. There
    the pointer goes to the element's place on the page instead.
    """
    info = await handle.evaluate(_DESCRIBE)
    if info["tag"] == "option" and await handle.evaluate(_PICK_OPTION):
        # A native dropdown is drawn by the system, outside the page.
        return
    # The human-shaped scroll takes many seconds to cross a long page. An
    # element more than a screen away is brought near first, as a person
    # does with the scrollbar, and the pointer does the rest.
    await handle.evaluate(_BRING_NEAR)
    try:
        await (handle.dblclick() if double else handle.click())
    except Exception as exc:
        if "humanize" not in str(exc):
            raise
        x, y = await _point(handle)
        await (page.mouse.dblclick(x, y) if double else page.mouse.click(x, y))


async def _fill(page, handle, text: str, *, clear: bool = True, submit: bool = False) -> None:
    """Put `text` into a field, in the way that kind of field takes it."""
    info = await handle.evaluate(_DESCRIBE)
    kind, tag = info["type"], info["tag"]
    if info["disabled"]:
        raise ValueError("that field is disabled")
    if tag == "select":
        try:
            await handle.select_option(label=text, timeout=3_000)
        except Exception:
            await handle.select_option(value=text, timeout=3_000)
    elif tag == "input" and kind in ("checkbox", "radio"):
        wanted = text.strip().lower()
        if wanted not in _YES | _NO:
            raise ValueError("a checkbox takes true or false. browser_click toggles it.")
        if (wanted in _YES) != info["checked"]:
            await _click(page, handle)
    elif tag == "input" and kind == "file":
        raise ValueError("that is a file input. Use browser_upload_files.")
    elif tag == "input" and kind in _PICKERS:
        await handle.fill(text)
    elif tag == "input" and kind == "range":
        await handle.evaluate(_SET_VALUE, text)
    else:
        await _click(page, handle)
        # Typed at the keyboard, into whatever the click focused. A page
        # often swaps the field for another one as it takes focus.
        if clear:
            await page.keyboard.press("ControlOrMeta+A")
            await page.keyboard.press("Backspace")
        await page.keyboard.type(text)
    if submit:
        await page.keyboard.press("Enter")


def interactive_lines(tree: str) -> str:
    """The lines of a snapshot an agent can act on: controls, links, headings, frames."""
    kept = []
    for line in tree.splitlines():
        text = line.strip()
        if not text.startswith("- ") or "[ref=" not in text:
            continue
        role = text[2:].split(" ", 1)[0].rstrip(":")
        if role in _INTERACTIVE:
            kept.append(text)
    return "\n".join(kept)


async def _snapshot(page, *, interactive: bool = False) -> str:
    tree = await page.aria_snapshot(mode="ai")
    return interactive_lines(tree) if interactive else tree


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

    async def after(note: str | None = None) -> str:
        """What a tool that changed the page returns: where the page is now, and what is on it."""
        # A click can navigate, open a tab, or raise a dialog. Give that a moment to land.
        await asyncio.sleep(0.25)
        page = await browser.open()
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=10_000)
        except Exception:
            pass
        lines = [f"url: {page.url}"]
        try:
            lines.append(f"title: {await page.title()}")
        except Exception:
            pass
        if note:
            lines.append(note)
        events, browser.events = browser.events, []
        for event in events:
            lines.append(json.dumps(event))
        try:
            tree = await _snapshot(page)
        except Exception as exc:
            lines.append(f"snapshot failed: {exc}")
            return "\n".join(lines)
        if len(tree) > SNAPSHOT_INLINE:
            short = interactive_lines(tree)
            lines.append(
                f"The page is large ({len(tree)} characters), so this is its controls, links, and headings. "
                "browser_snapshot returns the whole tree."
            )
            tree = short[:SNAPSHOT_INLINE]
        lines.extend(["", tree])
        return "\n".join(lines)

    @tool("Open the browser")
    async def browser_open(url: str | None = None) -> str:
        """Open the recorded browser, and go to `url` if one is given. Call this first."""
        page = await browser.open()
        if url:
            await page.goto(url, wait_until="domcontentloaded")
            return await after()
        return await _state(page)

    @tool("Go to a URL")
    async def browser_navigate(url: str) -> str:
        """Load `url` in the current tab. Returns the page that loaded, with a ref on each element."""
        page = await browser.open()
        await page.goto(url, wait_until="domcontentloaded")
        return await after()

    @tool("Go back")
    async def browser_back() -> str:
        """Go back one page in the current tab's history."""
        page = await browser.open()
        await page.go_back(wait_until="domcontentloaded")
        return await after()

    @tool("Page snapshot", read_only=True)
    async def browser_snapshot(interactive: bool = False) -> str:
        """The page as an accessibility tree, with a ref such as e12 on each element, including those in iframes.

        `interactive` returns only controls, links, headings, and frames, which is much shorter on a large page.
        """
        page = await browser.open()
        tree = await _snapshot(page, interactive=interactive)
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
        """Click an element, by its ref from the latest snapshot or by a CSS selector. Returns the page afterwards.

        Works on buttons, links, checkboxes, radios, and the options of a dropdown, in the page, an iframe, or shadow DOM.
        """
        page = await browser.open()
        await _click(page, await _target(page, ref, selector), double=double)
        return await after()

    @tool("Click at a point")
    async def browser_click_at(x: float, y: float) -> str:
        """Click at viewport coordinates, for a canvas or anything a snapshot does not name."""
        page = await browser.open()
        await page.mouse.click(x, y)
        return await after()

    @tool("Hover")
    async def browser_hover(ref: str | None = None, selector: str | None = None) -> str:
        """Move the pointer over an element, to open a menu or a tooltip. Returns the page afterwards."""
        page = await browser.open()
        handle = await _target(page, ref, selector)
        try:
            await handle.hover()
        except Exception as exc:
            if "humanize" not in str(exc):
                raise
            await page.mouse.move(*await _point(handle))
        return await after()

    @tool("Type into a field")
    async def browser_type(text: str, ref: str | None = None, selector: str | None = None, clear: bool = True, submit: bool = False) -> str:
        """Set a field to `text`, whatever kind of field it is. Returns the page afterwards.

        A text field, textarea, or rich-text editor is typed into key by key. A date is YYYY-MM-DD, a time HH:MM,
        a colour #rrggbb, a slider its number. A dropdown takes the label of the option. A checkbox takes true or false.
        `clear` empties a text field first. `submit` presses Enter after.
        """
        page = await browser.open()
        await _fill(page, await _target(page, ref, selector), text, clear=clear, submit=submit)
        return await after()

    @tool("Fill several fields")
    async def browser_fill_form(fields: list[dict], submit: bool = False) -> str:
        """Set several fields in one call. Each item is {"ref": "e12", "value": "..."} or {"selector": "...", "value": "..."}.

        Values follow the same rules as browser_type. `submit` presses Enter in the last field. Returns the page afterwards.
        """
        page = await browser.open()
        done = 0
        for number, field in enumerate(fields):
            try:
                handle = await _target(page, field.get("ref"), field.get("selector"))
                await _fill(page, handle, str(field.get("value", "")), submit=submit and number == len(fields) - 1)
            except Exception as exc:
                where = field.get("ref") or field.get("selector")
                return await after(f"stopped at field {number + 1} ({where}): {exc}. {done} of {len(fields)} were set.")
            done += 1
        return await after(f"{done} fields set")

    @tool("Press a key")
    async def browser_press_key(key: str) -> str:
        """Press a key or chord on the page, such as Enter, Escape, Tab, ArrowDown, or Control+A."""
        page = await browser.open()
        await page.keyboard.press(key)
        return await after()

    @tool("Choose an option")
    async def browser_select_option(values: list[str], ref: str | None = None, selector: str | None = None) -> str:
        """Choose options in a select element, by label or by value. Several values choose several in a multiple select."""
        page = await browser.open()
        handle = await _target(page, ref, selector)
        try:
            chosen = await handle.select_option(label=values, timeout=3_000)
        except Exception:
            chosen = await handle.select_option(value=values, timeout=3_000)
        return await after(f"selected: {json.dumps(chosen)}")

    @tool("Upload files")
    async def browser_upload_files(paths: list[str], ref: str | None = None, selector: str | None = None) -> str:
        """Set the files of a file input. `ref` is the input, shown in a snapshot as a button named after its label."""
        page = await browser.open()
        await (await _target(page, ref, selector)).set_input_files(paths)
        return await after(f"{len(paths)} file(s) set")

    @tool("Scroll")
    async def browser_scroll(ref: str | None = None, selector: str | None = None, dy: float = 0) -> str:
        """Scroll an element into the middle of the view, or scroll the page by `dy` pixels (negative is up)."""
        page = await browser.open()
        if ref or selector:
            await (await _target(page, ref, selector)).evaluate("e => e.scrollIntoView({block: 'center', inline: 'center'})")
        else:
            await page.mouse.wheel(0, dy)
        return await after()

    @tool("Answer dialogs")
    async def browser_handle_dialog(accept: bool = True, prompt_text: str | None = None) -> str:
        """Say how the next alert, confirm, or prompt is answered. Call it before the click that raises the dialog.

        Dialogs are accepted by default. `accept=false` dismisses them. `prompt_text` is typed into a prompt.
        The setting stays until it is changed.
        """
        browser.accept_dialogs = accept
        browser.dialog_text = prompt_text
        return json.dumps({"dialogs_will_be": "accepted" if accept else "dismissed", "prompt_text": prompt_text})

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
        """Wait for `text` to appear, for `gone` to disappear, or for `seconds` (at most 60). Returns the page afterwards."""
        page = await browser.open()
        if text:
            await page.get_by_text(text).first.wait_for(state="visible", timeout=NAV_TIMEOUT)
        if gone:
            await page.get_by_text(gone).first.wait_for(state="hidden", timeout=NAV_TIMEOUT)
        if seconds:
            await asyncio.sleep(min(max(seconds, 0), 60))
        return await after()

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
        browser.events = [event for event in browser.events if "new_tab" not in event]
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
