"""Scripts Firefox parsed, read from its remote debugger.

Ghostwire records this on Chrome with Debugger.scriptParsed. This Firefox
refuses that protocol. The same list comes from the browser's own debugger,
on 127.0.0.1, after the thread actor is attached.

The engine ships with zoom.stealth.debugger.force_detach on, and then attach
returns without listening. The launch turns that preference off. A page cannot
read it. The listener never pauses the page: a paused packet is resumed, and
no breakpoint is set. A dedicated worker is connected only after the
navigation has returned and its script has had time to load. Connecting
sooner keeps that script from being fetched. Attaching can still change
how the engine compiles a script.

The packet framing is the debugger transport: a decimal byte length, a colon,
then JSON. A bulk body is "bulk <actor> <type> <length>:" and then that many
bytes.
"""

from __future__ import annotations

import atexit
import inspect
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

PARSED_NAME = "scripts-parsed.jsonl"
FLAG_NAME = "debugger.ready"
SOURCE_CAP = 8_000_000
_SEEN_CAP = 4_000
# A worker target is announced before its script has been compiled. Asking
# for sources in that gap gets no reply, so the attach waits out the load.
_WORKER_DELAY = 1.2
_WORKER_TRIES = 5
_document_thread = threading.Event()

DEBUGGER_PREFS = {
    "devtools.debugger.remote-enabled": True,
    "devtools.debugger.prompt-connection": False,
    "devtools.debugger.force-local": True,
    "devtools.chrome.enabled": True,
    # ThreadActor.attach returns immediately while this stays true, so the
    # engine never emits newSource. The parsed-script record needs that event.
    "zoom.stealth.debugger.force_detach": False,
}

_FUNCTION_INTROS = frozenset(
    {"Function", "GeneratorFunction", "AsyncFunction", "AsyncGeneratorFunction"}
)
_SKIP_INTROS = frozenset({"wasm", "debugger eval"})

_listener: "Listener | None" = None
_guard = threading.Lock()
_warned = False


def prepare_output(out: Path) -> None:
    """Remember where this session records, and clear a stale debugger flag.

    The flag is created only after the listener is attached. The recorder
    process reads it to leave the site's Content-Security-Policy unchanged.
    """
    folder = Path(out).resolve()
    os.environ["OBY_OUT"] = str(folder)
    os.environ.setdefault("OBY_PARSED_FLAG", f"/tmp/oby-debugger-{os.getpid()}.ready")
    flag = os.environ.get("OBY_PARSED_FLAG")
    if flag:
        try:
            os.remove(flag)
        except OSError:
            pass


def kind_for(url: str, introduction: str) -> str | None:
    """Map a Firefox introduction type onto a scripts.json kind."""
    intro = introduction or ""
    if intro in _SKIP_INTROS:
        return None
    if url.lower().startswith("blob:"):
        return "blob"
    if intro == "eval":
        return "eval"
    if intro in _FUNCTION_INTROS:
        return "function"
    if intro == "domTimer":
        return "timer"
    if intro == "javascriptURL":
        return "eval"
    if script_resource(url):
        return "network"
    return "inline"


def script_resource(url: str) -> bool:
    if not url:
        return False
    lowered = url.lower()
    if lowered.startswith("data:"):
        meta = lowered.split(",", 1)[0]
        return "javascript" in meta or "ecmascript" in meta
    path = urlsplit(url).path.lower()
    return path.endswith((".js", ".mjs", ".cjs"))


def skip_url(url: str) -> bool:
    """Browser chrome and the debugger's own files are not the page."""
    if not url:
        return False
    lowered = url.lower()
    if lowered.startswith(("chrome://", "resource://", "moz-extension://", "jar:")):
        return True
    if "extensioncontent.sys.mjs" in lowered:
        return True
    if lowered.startswith("about:") and not lowered.startswith(("about:blank", "about:srcdoc")):
        return True
    return False


def arm_launch(launcher) -> None:
    """Ask this Firefox to listen on loopback and to report parsed scripts."""
    from oby.enginefix import patch_engine

    patch_engine()
    args = list(getattr(launcher, "_extra_args", None) or [])
    port = _port_in_args(args)
    if port is None:
        port = allocate_port()
        args.extend(["--start-debugger-server", str(port)])
    launcher._extra_args = args
    prefs = dict(getattr(launcher, "_extra_prefs", None) or {})
    prefs.update(DEBUGGER_PREFS)
    launcher._extra_prefs = prefs
    launcher._oby_debugger_port = port


def install_on(*classes) -> None:
    for cls in classes:
        original = cls.__init__
        if getattr(original, "_oby_parsed", False):
            continue

        def wrapped(self, *args, original=original, **kwargs):
            original(self, *args, **kwargs)
            try:
                arm_launch(self)
            except Exception as exc:
                _warn(f"oby: could not enable parsed scripts: {exc}")

        wrapped._oby_parsed = True  # type: ignore[attr-defined]
        cls.__init__ = wrapped  # type: ignore[method-assign]


def start_parsed(launcher) -> bool:
    """Connect to the debugger started for this browser. True when it is listening."""
    global _listener
    port = getattr(launcher, "_oby_debugger_port", None)
    folder = os.environ.get("OBY_OUT")
    if not isinstance(port, int) or not folder:
        if not folder:
            _warn("oby: parsed scripts need an output folder. Using the page hook.")
        return False
    listener = Listener(port, Path(folder) / PARSED_NAME)
    with _guard:
        previous = _listener
        _listener = listener
    if previous is not None:
        previous.stop()
    listener.start()
    if listener.wait_ready(30):
        return True
    detail = listener.error
    name = type(detail).__name__ if isinstance(detail, BaseException) else "unavailable"
    detail_text = ""
    if isinstance(detail, BaseException) and str(detail):
        detail_text = f": {detail}"
    _warn(f"oby: parsed scripts unavailable ({name}{detail_text}). Using the page hook.")
    listener.stop()
    return False


def wait_until_attached(timeout: float = 12) -> bool:
    """Block until a page thread is attached and reporting the scripts it parses."""
    listener = _listener
    if listener is None:
        return False
    return listener._page_ready.wait(timeout)


def arm_navigation(result) -> None:
    """Hold page loads until the debugger is attached to that page."""
    if callable(getattr(result, "goto", None)):
        _arm_goto(result)
    _arm_existing(result)
    for name in ("new_page", "new_context"):
        _wrap_factory(result, name)


def _arm_existing(result) -> None:
    pages = getattr(result, "pages", None)
    if pages:
        for page in list(pages):
            _arm_goto(page)
    contexts = getattr(result, "contexts", None)
    if contexts:
        for context in list(contexts):
            _arm_existing(context)


def _wrap_factory(result, name: str) -> None:
    original = getattr(result, name, None)
    if not callable(original) or getattr(original, "_oby_nav", False):
        return
    if inspect.iscoroutinefunction(original):

        async def wrapped(*args, **kwargs):
            created = await original(*args, **kwargs)
            arm_navigation(created)
            return created
    else:

        def wrapped(*args, **kwargs):
            created = original(*args, **kwargs)
            arm_navigation(created)
            return created

    wrapped._oby_nav = True  # type: ignore[attr-defined]
    try:
        setattr(result, name, wrapped)
    except Exception:
        return


def begin_document() -> None:
    """The next document has not reached its scripts yet."""
    _document_thread.clear()


def mark_document_thread() -> None:
    """The page thread is attached, so the document may run."""
    _document_thread.set()


def wait_for_document_thread(timeout: float = 8) -> bool:
    return _document_thread.wait(timeout)


def _route_pattern(url: str) -> str:
    """One Playwright glob for this document. A function matcher becomes ``**/*``."""
    literal = url.split("#", 1)[0]
    return "".join(f"\\{char}" if char in "\\*?{}" else char for char in literal)


def _drop_route(context, pattern: str, handler) -> None:
    """Remove this document's route. A route left installed blocks a worker."""
    uninstall = getattr(context, "unroute", None)
    if not callable(uninstall):
        return
    try:
        return uninstall(pattern, handler)
    except Exception:
        return None


# The new page thread usually attaches while this document is paused, which
# is what lets a dedicated worker be reported. Cap the pause so a thread
# that arrives only with the body cannot hide the visit: the request is
# continued when the cap is reached.
_DOCUMENT_HOLD = 8.0


def _document_navigation(route) -> bool:
    request = getattr(route, "request", None)
    kind = getattr(request, "resource_type", "") if request is not None else ""
    navigation = getattr(request, "is_navigation_request", None)
    if kind != "document":
        return False
    return not (callable(navigation) and not navigation())


def _hold_documents(page, url: str | None = None) -> None:
    """Pause this document briefly, then send the browser's own request.

    The watcher has to be listening before a dedicated worker starts. The
    pause is capped. The route is removed before the body is released, and
    the request is continued even when that removal fails.
    """
    if not url or os.environ.get("OBY_PARSED_NO_HOLD") == "1":
        return
    context = getattr(page, "context", None)
    if context is None:
        return
    held = getattr(context, "_oby_held_urls", None)
    if not isinstance(held, set):
        held = set()
        try:
            context._oby_held_urls = held
        except Exception:
            return
    pattern = _route_pattern(url)
    if not pattern or pattern in held:
        return
    install = getattr(context, "route", None)
    if not callable(install):
        return

    def release(route) -> None:
        if not _document_navigation(route):
            route.continue_()
            return
        wait_for_document_thread(_DOCUMENT_HOLD)
        try:
            _drop_route(context, pattern, release)
        finally:
            route.continue_()

    if inspect.iscoroutinefunction(getattr(page, "goto", None)):

        async def handler(route):
            if not _document_navigation(route):
                await route.continue_()
                return
            import asyncio

            await asyncio.get_running_loop().run_in_executor(
                None, wait_for_document_thread, _DOCUMENT_HOLD
            )
            try:
                dropped = _drop_route(context, pattern, handler)
                if inspect.isawaitable(dropped):
                    await dropped
            finally:
                await route.continue_()
    else:
        handler = release
    try:
        install(pattern, handler)
    except Exception:
        return
    held.add(pattern)


def _arm_goto(page) -> None:
    goto = getattr(page, "goto", None)
    if not callable(goto) or getattr(goto, "_oby_nav", False):
        return
    if inspect.iscoroutinefunction(goto):

        async def wrapped(url, *args, **kwargs):
            wait_until_attached()
            begin_document()
            _hold_documents(page, str(url))
            return await goto(url, *args, **kwargs)
    else:

        def wrapped(url, *args, **kwargs):
            wait_until_attached()
            begin_document()
            _hold_documents(page, str(url))
            return goto(url, *args, **kwargs)

    wrapped._oby_nav = True  # type: ignore[attr-defined]
    try:
        page.goto = wrapped
    except Exception:
        return


def stop_listener() -> None:
    """Flush the parsed-script log. Safe to call more than once."""
    global _listener
    with _guard:
        listener = _listener
        _listener = None
    if listener is not None:
        listener.stop()


def allocate_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _port_in_args(args: list) -> int | None:
    if "--start-debugger-server" not in args:
        return None
    index = args.index("--start-debugger-server")
    if index + 1 >= len(args):
        return None
    try:
        return int(args[index + 1])
    except (TypeError, ValueError):
        return None


class PacketStream:
    """One debugger connection. Packets stay framed across partial reads."""

    def __init__(self, sock, stop: threading.Event):
        self.sock = sock
        self.stop = stop
        self.buf = b""

    def read_packet(self, timeout: float):
        deadline = time.monotonic() + timeout
        while True:
            if self.stop.is_set():
                raise EOFError
            if self._ready():
                return self._take()
            if time.monotonic() >= deadline:
                raise TimeoutError
            if self.buf and not self.buf[:1].isdigit() and not b"bulk ".startswith(self.buf):
                raise ValueError("unrecognized debugger packet")
            if len(self.buf) > 128 and b":" not in self.buf:
                raise ValueError("debugger packet header never finished")
            remaining = deadline - time.monotonic()
            try:
                self.sock.settimeout(min(0.5, max(0.05, remaining)))
            except OSError:
                pass
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise EOFError
            self.buf += chunk

    def _ready(self) -> bool:
        if self.buf.startswith(b"bulk "):
            if b":" not in self.buf:
                return False
            header = self.buf.split(b":", 1)[0]
            parts = header.split(b" ")
            if len(parts) != 4:
                return False
            try:
                length = int(parts[3])
            except ValueError:
                return False
            return len(self.buf) >= len(header) + 1 + length
        if b":" not in self.buf:
            return False
        header = self.buf.split(b":", 1)[0]
        if not header.isdigit():
            return False
        return len(self.buf) >= len(header) + 1 + int(header)

    def _take(self):
        if self.buf.startswith(b"bulk "):
            header, rest = self.buf.split(b":", 1)
            parts = header.split(b" ")
            length = int(parts[3])
            self.buf = rest[length:]
            return {
                "_bulk": True,
                "actor": parts[1].decode("ascii", "replace"),
                "bulk_type": parts[2].decode("ascii", "replace"),
                "data": rest[:length],
            }
        header, rest = self.buf.split(b":", 1)
        length = int(header)
        self.buf = rest[length:]
        return json.loads(rest[:length].decode("utf-8"))


class Listener:
    def __init__(self, port: int, dest: Path):
        self.port = port
        self.dest = dest
        self.ready = threading.Event()
        self.attached = False
        self.error: BaseException | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._sock = None
        self._stream: PacketStream | None = None
        self.tab: str | None = None
        self.thread: str | None = None
        self._threads: set[str] = set()
        self._seen: set[str] = set()
        self._queue: list[dict] = []
        self._new_threads: list[str] = []
        self._later: list[tuple[float, str]] = []
        self._later_ids: set[str] = set()
        self._worker_tries: dict[str, int] = {}
        self._pending: dict | None = None
        self._write_lock = threading.Lock()
        self._debug_left = 80
        self._known_tabs: set[str] = set()
        self._tab_queue: list[str] = []
        self._watch_queue: list[str] = []
        self._watched: set[str] = set()
        self._tabs_dirty = False
        self._page_ready = threading.Event()
        self._content_attached = False
        self._rescan_at = 0.0
        self._windows: set[str] = set()
        self._watcher: str | None = None
        self._workers_watched = False
        self._pause_threads: set[str] = set()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="oby-parsed", daemon=True)
        self._thread.start()

    def wait_ready(self, timeout: float) -> bool:
        self.ready.wait(timeout)
        return self.attached

    def stop(self) -> None:
        self._stop.set()
        sock = self._sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=3)

    def _run(self) -> None:
        try:
            deadline = time.monotonic() + 22
            last: Exception | None = None
            while time.monotonic() < deadline:
                if self._stop.is_set():
                    raise EOFError
                try:
                    self._connect()
                    self._handshake()
                except TimeoutError as exc:
                    last = exc
                    self._step(f"retry {exc}")
                    self._reset_link()
                    time.sleep(0.3)
                    continue
                self.attached = True
                _mark_flag()
                self.ready.set()
                self._loop()
                return
            raise last or TimeoutError("debugger sent no greeting")
        except Exception as exc:
            self.error = exc
            if not self.ready.is_set():
                self.attached = False
            self.ready.set()
        finally:
            self._close()

    def _connect(self) -> None:
        deadline = time.monotonic() + 8
        last: Exception | None = None
        while time.monotonic() < deadline:
            if self._stop.is_set():
                raise EOFError
            try:
                # create_connection's timeout stays on the socket. A later
                # read would then die while the tab list is still arriving.
                sock = socket.create_connection(("127.0.0.1", self.port), 2)
            except (ConnectionRefusedError, TimeoutError, OSError) as exc:
                last = exc
                time.sleep(0.25)
                continue
            preview = _opening(sock)
            if not preview:
                # The first accept can stay silent. A new connection gets the greeting.
                self._step(f"silent {self.port}")
                _close_socket(sock)
                time.sleep(0.25)
                continue
            sock.settimeout(None)
            self._sock = sock
            self._stream = PacketStream(sock, self._stop)
            self._stream.buf = preview
            self._step(f"connected {self.port} bytes={len(preview)}")
            return
        raise last or TimeoutError("debugger sent no greeting")

    def _handshake(self) -> None:
        # The buffer is the greeting. This Firefox expects connect before any
        # other root request. A listTabs sent before the greeting is dropped
        # and can leave the root actor waiting, so this is the first request.
        _send(self._sock, {"to": "root", "type": "connect", "frontendVersion": "159.0"})
        self._step("request connect")
        self._wait(
            lambda pkt: pkt.get("from") == "root" and "applicationType" not in pkt,
            4,
        )
        _send(self._sock, {"to": "root", "type": "listTabs"})
        self._step("request tabs")
        self._wait(lambda pkt: _take_tab(self, pkt), 6)
        if not self.tab:
            # The browser has no page yet. listTabs armed tabListChanged, and
            # the read loop attaches the page when it opens.
            self._step("waiting for a tab")
            return
        _send(self._sock, {"to": self.tab, "type": "getTarget"})
        found = self._wait(
            lambda pkt: isinstance(pkt.get("frame"), dict) and bool(pkt["frame"].get("threadActor")),
            12,
        )
        self.thread = str(found["frame"]["threadActor"])
        self._attach(self.thread, required=True)
        self._watch_children(self.tab)

    def _attach(self, thread: str, *, required: bool) -> None:
        if thread in self._threads:
            return
        self._threads.add(thread)
        hold_workers = thread in self._pause_threads
        self._pause_threads.discard(thread)
        # Do not set pauseWorkersUntilAttach. That pause is only released when
        # the debugger panel attaches the worker, and a worker stuck there never
        # fetches its script. The watcher already pauses a worker at startup and
        # releases it when the connection is up.
        options = {"pause": False}
        self._step(f"attach {thread}")
        _send(self._sock, {"to": thread, "type": "attach", "options": options})
        try:
            ack = self._wait(lambda pkt: pkt.get("from") == thread or bool(pkt.get("error")), 2)
        except TimeoutError:
            ack = {}
        if hold_workers:
            mark_document_thread()
        if ack.get("type") == "paused" and isinstance(ack.get("from"), str) and self._sock is not None:
            _send(self._sock, {"to": ack["from"], "type": "resume"})
        if ack.get("error") and required:
            raise RuntimeError(str(ack.get("error")))
        if self._sock is None:
            return
        _send(self._sock, {"to": thread, "type": "sources"})
        # The page answers at once. A worker that is still starting does not
        # answer this round; it is asked again once its script can be running.
        try:
            reply = self._wait(
                lambda pkt: isinstance(pkt.get("sources"), list) and pkt.get("from") == thread,
                2,
            )
        except TimeoutError:
            self._threads.discard(thread)
            if "workerTarget" in thread:
                self._retry_worker(thread)
            elif required:
                raise
            return
        self._content_attached = True
        self._maybe_page_ready()
        listed = [item for item in (reply.get("sources") or []) if isinstance(item, dict)]
        self._step(f"sources {len(listed)}")
        for item in listed:
            if isinstance(item, dict):
                self._note(item)

    def _watch_children(self, tab: str | None) -> None:
        """Frames and workers have their own threads. Do not watch source resources.

        The resource watcher attaches and then turns newSource off. The thread
        event is the one this Firefox actually emits. A worker's scripts arrive
        on the worker target's thread only if the watcher was listening when
        that worker started. The window's worker-descriptor target does not
        answer on this engine.
        """
        if not tab or tab in self._watched or self._sock is None:
            self._maybe_page_ready()
            return
        self._watched.add(tab)
        self._step(f"watch {tab}")
        try:
            self._arm_watcher(tab)
        finally:
            self._maybe_page_ready()

    def _maybe_page_ready(self) -> None:
        if self._content_attached and self._watched:
            self._page_ready.set()

    def _arm_watcher(self, tab: str) -> None:
        _send(
            self._sock,
            {
                "to": tab,
                "type": "getWatcher",
                "isServerTargetSwitchingEnabled": True,
            },
        )
        try:
            reply = self._wait(lambda pkt, tab=tab: _watcher_reply(pkt, tab), 4)
        except TimeoutError:
            return
        watcher = _watcher_id(reply)
        if not watcher:
            return
        self._watcher = watcher
        _send(self._sock, {"to": watcher, "type": "watchTargets", "targetType": "frame"})
        try:
            self._wait(lambda pkt, watcher=watcher: _watcher_ack(pkt, watcher), 2)
        except TimeoutError:
            pass
        # Before the real page loads. The session then includes workers, so the
        # page's content process is already listening when a worker starts.
        # Asking after the worker is running never returns its scripts.
        self._watch_workers()

    def _watch_workers(self) -> None:
        """Ask the watcher for worker threads. One request covers later workers too."""
        watcher = self._watcher
        if not watcher or self._workers_watched or self._sock is None:
            return
        self._workers_watched = True
        self._rewatch_workers()

    def _rewatch_workers(self) -> None:
        watcher = self._watcher
        if not watcher or self._sock is None:
            return
        self._step("watch workers")
        _send(self._sock, {"to": watcher, "type": "watchTargets", "targetType": "worker"})

    def _loop(self) -> None:
        while not self._stop.is_set():
            self._promote_workers()
            # The document thread first, so its workers may start. Then one
            # queued source, so a slow worker cannot hold the text already found.
            page = [item for item in self._new_threads if "workerTarget" not in item]
            if page:
                self._new_threads = [item for item in self._new_threads if item not in page]
                self._new_threads.extend(page[1:])
                self._attach(page[0], required=False)
                continue
            if self._pending is None and self._queue:
                self._begin(self._queue.pop(0))
                continue
            if self._new_threads:
                self._attach(self._new_threads.pop(0), required=False)
                continue
            if self._watch_queue and self._sock is not None:
                self._watch_children(self._watch_queue.pop(0))
                continue
            if self._tab_queue and self._sock is not None and self._pending is None:
                _send(self._sock, {"to": self._tab_queue.pop(0), "type": "getTarget"})
                continue
            if self._tabs_dirty and self._sock is not None and self._pending is None:
                self._tabs_dirty = False
                _send(self._sock, {"to": "root", "type": "listTabs"})
                continue
            if self._rescan_at and time.monotonic() >= self._rescan_at and self._sock is not None:
                self._rescan_at = 0.0
                for thread in list(self._threads):
                    _send(self._sock, {"to": thread, "type": "sources"})
                self._step("rescan")
                continue
            try:
                pkt = self._stream.read_packet(0.4)
            except TimeoutError:
                self._expire()
                continue
            except (EOFError, OSError, ValueError):
                break
            if self._pending is not None and self._consume(pkt):
                continue
            self._observe(pkt)

    def _begin(self, form: dict) -> None:
        actor = form.get("actor")
        if not isinstance(actor, str) or self._sock is None:
            return
        _send(self._sock, {"to": actor, "type": "source"})
        self._pending = {
            "actor": actor,
            "form": form,
            "stage": "source",
            "deadline": time.monotonic() + 8,
        }

    def _expire(self) -> None:
        pending = self._pending
        if pending is None or time.monotonic() < pending["deadline"]:
            return
        initial = pending.get("initial")
        if isinstance(initial, str) and initial:
            self._save(pending["form"], initial, truncated=True)
        self._pending = None

    def _consume(self, pkt: dict) -> bool:
        pending = self._pending
        if pending is None:
            return False
        if pkt.get("_bulk"):
            actor = pkt.get("actor")
            if actor not in {pending["actor"], pending.get("long_actor")}:
                return False
            text = bytes(pkt.get("data") or b"").decode("utf-8", "replace")
            self._save(pending["form"], text, truncated=False)
            self._pending = None
            return True
        sender = pkt.get("from")
        if sender not in {pending["actor"], pending.get("long_actor")}:
            return False
        if pkt.get("type") == "paused" and isinstance(sender, str) and self._sock is not None:
            _send(self._sock, {"to": sender, "type": "resume"})
            return True
        if pkt.get("error"):
            self._pending = None
            return True
        if pending["stage"] == "source":
            ctype = str(pkt.get("contentType") or "")
            if "wasm" in ctype.lower():
                self._pending = None
                return True
            source = pkt.get("source")
            if source is None and isinstance(pkt.get("result"), dict):
                source = pkt["result"].get("source")
            if source is None:
                return False
            text, long_actor, length = _interpret(source)
            if long_actor and self._sock is not None:
                _send(
                    self._sock,
                    {"to": long_actor, "type": "substring", "start": 0, "end": length},
                )
                pending["stage"] = "substring"
                pending["long_actor"] = long_actor
                pending["length"] = length
                pending["initial"] = text or ""
                pending["deadline"] = time.monotonic() + 8
                return True
            if text:
                self._save(pending["form"], text, truncated=False)
            self._pending = None
            return True
        text = pkt.get("substring")
        if not isinstance(text, str):
            return False
        length = int(pending.get("length") or len(text))
        self._save(pending["form"], text, truncated=len(text) < length)
        self._pending = None
        return True

    def _observe(self, pkt: dict) -> None:
        if not isinstance(pkt, dict):
            return
        self._debug(pkt)
        if pkt.get("applicationType") == "browser":
            self._step("greeting")
        if pkt.get("type") == "paused" and isinstance(pkt.get("from"), str) and self._sock is not None:
            _send(self._sock, {"to": pkt["from"], "type": "resume"})
            return
        if pkt.get("type") == "tabListChanged":
            self._tabs_dirty = True
            return
        if pkt.get("type") == "workerListChanged":
            sender = pkt.get("from")
            if isinstance(sender, str):
                self._list_workers(sender)
            return
        if pkt.get("type") == "connected":
            thread = _thread_id(pkt)
            if thread:
                self._step(f"worker thread {thread}")
                self._queue_thread(thread)
            return
        if isinstance(pkt.get("tabs"), list):
            self._enqueue_tabs(pkt["tabs"])
            return
        if pkt.get("type") == "target-available-form" and isinstance(pkt.get("target"), dict):
            target = pkt["target"]
            url = target.get("url") if isinstance(target.get("url"), str) else ""
            self._step(
                "target "
                + ",".join(str(key) for key in list(target)[:12])
                + " thread="
                + str(target.get("threadActor") or "")
                + " scheme="
                + (url.split(":", 1)[0] if url else "none")
            )
            self._note_target(target)
            self._remember_window(target)
            return
        frame = pkt.get("frame")
        if isinstance(frame, dict) and (_thread_id(frame) or is_window_target(frame)):
            self._queue_thread(_thread_id(frame), pause=_page_url(frame))
            sender = pkt.get("from")
            if isinstance(sender, str) and sender not in self._watched:
                self._watch_queue.append(sender)
            self._remember_window(frame)
            return
        # A destroyed target still carries its thread id. Attaching that
        # thread pulls in browser workers and steals the read loop.
        if pkt.get("type") == "target-destroyed-form":
            return
        for key in ("target", "form", "workerTarget"):
            nested = pkt.get(key)
            if not isinstance(nested, dict) or not _thread_id(nested):
                continue
            url = nested.get("url") if isinstance(nested.get("url"), str) else ""
            if skip_url(url):
                return
            self._queue_thread(_thread_id(nested))
            return
        if pkt.get("type") == "newSource" and isinstance(pkt.get("source"), dict):
            self._note(pkt["source"])
            url = pkt["source"].get("url") if isinstance(pkt["source"].get("url"), str) else ""
            if url.startswith("http") and not self._rescan_at:
                # The document scripts are in. Ask again so eval and injected
                # scripts compiled during the load are included.
                self._rescan_at = time.monotonic() + 0.6
            return
        sources = pkt.get("sources")
        if isinstance(sources, list):
            for item in sources:
                if isinstance(item, dict):
                    self._note(item)
            return
        if isinstance(pkt.get("workers"), list):
            self._step(f"workers {len(pkt['workers'])}")
            for worker in pkt["workers"]:
                if not isinstance(worker, dict):
                    continue
                actor = worker.get("actor")
                thread = _thread_id(worker)
                url = worker.get("url") if isinstance(worker.get("url"), str) else ""
                self._step(
                    "worker "
                    + (actor or "")
                    + " thread="
                    + (thread or "none")
                    + " scheme="
                    + (url.split(":", 1)[0] if url else "none")
                )
                self._queue_thread(thread)
            return

    def _enqueue_tabs(self, tabs: list) -> None:
        for tab in tabs:
            if not isinstance(tab, dict):
                continue
            actor = tab.get("actor") or tab.get("actorID")
            if not isinstance(actor, str) or actor in self._known_tabs:
                continue
            url = tab.get("url") if isinstance(tab.get("url"), str) else ""
            if skip_url(url):
                self._known_tabs.add(actor)
                continue
            self._known_tabs.add(actor)
            self._tab_queue.append(actor)
            self._step(f"tab {actor}")

    def _queue_thread(self, thread: str | None, *, pause: bool = False) -> None:
        if not isinstance(thread, str) or thread in self._threads or thread in self._new_threads:
            return
        if thread in self._later_ids:
            if pause:
                self._pause_threads.add(thread)
            return
        if pause:
            self._pause_threads.add(thread)
        if "workerTarget" in thread:
            # The target arrives before the worker script exists. Attach after
            # the load, when sources() can still see the running script.
            self._later.append((time.monotonic() + _WORKER_DELAY, thread))
            self._later_ids.add(thread)
            return
        self._new_threads.append(thread)

    def _promote_workers(self) -> None:
        if not self._later:
            return
        now = time.monotonic()
        waiting: list[tuple[float, str]] = []
        for when, thread in self._later:
            if when > now or thread in self._threads or thread in self._new_threads:
                if when > now:
                    waiting.append((when, thread))
                else:
                    self._later_ids.discard(thread)
                continue
            self._later_ids.discard(thread)
            self._new_threads.append(thread)
        self._later = waiting

    def _retry_worker(self, thread: str) -> None:
        tries = self._worker_tries.get(thread, 0) + 1
        self._worker_tries[thread] = tries
        if tries > _WORKER_TRIES or thread in self._later_ids or thread in self._new_threads:
            return
        self._later.append((time.monotonic() + 0.8, thread))
        self._later_ids.add(thread)

    def _remember_window(self, target) -> None:
        if not is_window_target(target):
            return
        actor = target.get("actor")
        if not isinstance(actor, str) or actor in self._windows:
            return
        self._windows.add(actor)
        self._list_workers(actor)

    def _list_workers(self, actor: str) -> None:
        """Ask for dedicated workers. The reply arms the one-shot workerListChanged event."""
        if self._sock is None or not actor:
            return
        _send(self._sock, {"to": actor, "type": "listWorkers"})
        self._step(f"listWorkers {actor}")

    def _note(self, form: dict) -> None:
        actor = form.get("actor")
        if not isinstance(actor, str) or actor in self._seen or len(self._seen) >= _SEEN_CAP:
            return
        url = form.get("url") if isinstance(form.get("url"), str) else ""
        intro = form.get("introductionType") if isinstance(form.get("introductionType"), str) else ""
        if skip_url(url) or intro in _SKIP_INTROS:
            self._seen.add(actor)
            return
        self._seen.add(actor)
        self._queue.append(form)

    def _note_target(self, target) -> None:
        if not isinstance(target, dict):
            return
        if target.get("type") in {"process", "parent-process"}:
            return
        url = target.get("url") if isinstance(target.get("url"), str) else ""
        if skip_url(url):
            return
        thread = _thread_id(target)
        if thread is None:
            for key in ("target", "form", "worker", "frame"):
                thread = _thread_id(target.get(key))
                if thread:
                    break
        self._queue_thread(
            thread,
            pause=bool(is_window_target(target) and _page_url(target)),
        )

    def _save(self, form: dict, text: str, *, truncated: bool) -> None:
        if not text or _own_hook(text):
            return
        url = form.get("url") if isinstance(form.get("url"), str) else ""
        if skip_url(url):
            return
        intro = form.get("introductionType") if isinstance(form.get("introductionType"), str) else ""
        kind = kind_for(url, intro)
        if kind is None:
            return
        if len(text) > SOURCE_CAP:
            text = text[:SOURCE_CAP]
            truncated = True
        item = {
            "kind": kind,
            "url": url[:2048],
            "source": text,
            "introduction": intro,
        }
        if truncated:
            item["truncated"] = True
        line = json.dumps(item, ensure_ascii=False) + "\n"
        with self._write_lock:
            self.dest.parent.mkdir(parents=True, exist_ok=True)
            with self.dest.open("a", encoding="utf-8") as handle:
                handle.write(line)
                handle.flush()

    def _wait(self, pred, timeout: float):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._stream is None:
                raise EOFError
            try:
                pkt = self._stream.read_packet(min(0.5, max(0.05, deadline - time.monotonic())))
            except TimeoutError:
                continue
            if not isinstance(pkt, dict):
                continue
            if pred(pkt):
                self._debug(pkt)
                return pkt
            # A worker attaching must not swallow the source text already requested.
            if self._pending is not None and self._consume(pkt):
                continue
            self._observe(pkt)
        buf = self._stream.buf if self._stream is not None else b""
        self._step(f"timeout bytes={len(buf)} head={buf[:80]!r}")
        raise TimeoutError("debugger reply timed out")

    def _step(self, message: str) -> None:
        if os.environ.get("OBY_PARSED_DEBUG") == "1":
            print(f"oby-parsed: {message}", file=sys.stderr)

    def _debug(self, pkt: dict) -> None:
        if os.environ.get("OBY_PARSED_DEBUG") != "1" or self._debug_left <= 0:
            return
        self._debug_left -= 1
        shown: dict[str, object] = {}
        for key in ("type", "error", "message"):
            if key in pkt:
                shown[key] = str(pkt.get(key))[:120]
        form = pkt.get("source") if isinstance(pkt.get("source"), dict) else None
        if form is not None:
            shown["intro"] = form.get("introductionType")
            shown["url"] = str(form.get("url") or "")[:100]
        target = pkt.get("target") if isinstance(pkt.get("target"), dict) else None
        if target is not None:
            shown["target_type"] = target.get("type")
            if pkt.get("type") == "target-available-form":
                shown["target_keys"] = ",".join(str(key) for key in list(target)[:8])
        if isinstance(pkt.get("frame"), dict):
            shown["frame"] = True
        if not shown:
            shown["keys"] = ",".join(str(key) for key in list(pkt)[:6])
        print(f"oby-parsed: {shown}", file=sys.stderr)

    def _reset_link(self) -> None:
        self._close()
        self._stream = None
        self.tab = None
        self.thread = None
        self._threads.clear()
        self._known_tabs.clear()
        self._tab_queue.clear()
        self._watch_queue.clear()
        self._watched.clear()
        self._tabs_dirty = False
        self._pending = None
        self._new_threads.clear()
        self._later.clear()
        self._later_ids.clear()
        self._worker_tries.clear()
        self._queue.clear()
        self._content_attached = False
        self._page_ready.clear()
        self._rescan_at = 0.0
        self._windows.clear()
        self._watcher = None
        self._workers_watched = False
        self._pause_threads.clear()

    def _close(self) -> None:
        sock = self._sock
        self._sock = None
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _opening(sock) -> bytes:
    """Return the greeting the server writes on accept.

    Sending a request before that greeting is parsed drops it: the packet
    handler is not installed yet, and a dropped listTabs leaves the root
    actor unable to answer. A socket that stays quiet is not a session we
    can record.
    """
    try:
        sock.settimeout(2)
        return sock.recv(65536)
    except socket.timeout:
        return b""
    except OSError:
        return b""


def _close_socket(sock) -> None:
    try:
        sock.close()
    except OSError:
        pass


def _send(sock, obj: dict) -> None:
    if sock is None:
        return
    raw = json.dumps(obj, separators=(",", ":")).encode()
    sock.sendall(f"{len(raw)}:".encode("ascii") + raw)


def _take_tab(listener: Listener, pkt: dict) -> bool:
    if pkt.get("from") != "root" or "tabs" not in pkt:
        return False
    tabs = pkt.get("tabs")
    if isinstance(tabs, dict):
        tabs = tabs.get("tabs")
    if not isinstance(tabs, list):
        return False
    listener._step(f"tabs {len(tabs)}")
    if tabs and isinstance(tabs[0], dict):
        listener._step("tab keys " + ",".join(str(key) for key in list(tabs[0])[:8]))
    listener._enqueue_tabs(tabs)
    chosen = next((tab for tab in tabs if isinstance(tab, dict) and tab.get("selected")), None)
    if not isinstance(chosen, dict):
        chosen = next((tab for tab in tabs if isinstance(tab, dict)), None)
    actor = None
    if isinstance(chosen, dict):
        raw = chosen.get("actor") or chosen.get("actorID")
        if isinstance(raw, str):
            actor = raw
    if actor:
        listener.tab = actor
        if actor in listener._tab_queue:
            listener._tab_queue.remove(actor)
    return True


def _watcher_reply(pkt: dict, tab: str | None) -> bool:
    if pkt.get("error") and pkt.get("from") == tab:
        return True
    return _watcher_id(pkt) is not None and pkt.get("from") == tab


def _watcher_id(pkt: dict) -> str | None:
    watcher = pkt.get("watcher")
    if isinstance(watcher, dict) and isinstance(watcher.get("actor"), str):
        return watcher["actor"]
    if isinstance(watcher, str):
        return watcher
    actor = pkt.get("actor")
    if isinstance(actor, str) and pkt.get("from") not in {None, "root", actor}:
        return actor
    return None


def _watcher_ack(pkt: dict, watcher: str) -> bool:
    if pkt.get("from") != watcher:
        return False
    return pkt.get("type") not in {
        "target-available-form",
        "target-destroyed-form",
        "resources-available-array",
        "resources-updated-array",
        "resources-destroyed-array",
    }


def _interpret(source) -> tuple[str | None, str | None, int]:
    if isinstance(source, str):
        return source, None, len(source)
    if not isinstance(source, dict):
        return None, None, 0
    kind = str(source.get("type") or "")
    if "wasm" in kind.lower() or kind.lower() in {"arraybuffer", "array-buffer"}:
        return None, None, 0
    if "initial" in source or kind == "longString":
        initial = source.get("initial") if isinstance(source.get("initial"), str) else ""
        try:
            length = int(source.get("length") or 0)
        except (TypeError, ValueError):
            length = len(initial)
        actor = source.get("actor") if isinstance(source.get("actor"), str) else None
        if actor and length > len(initial):
            return initial, actor, length
        return initial, None, len(initial)
    return None, None, 0


def _page_url(target) -> bool:
    if not isinstance(target, dict):
        return False
    url = target.get("url") if isinstance(target.get("url"), str) else ""
    return url.startswith(("http://", "https://"))


def is_window_target(target: dict) -> bool:
    """A window target is the actor that lists the document's dedicated workers."""
    if not isinstance(target, dict) or not isinstance(target.get("actor"), str):
        return False
    kind = str(target.get("targetType") or "")
    if kind in {"worker", "service_worker", "shared_worker", "process", "parent-process"}:
        return False
    if kind == "frame":
        return True
    return "innerWindowId" in target or "browsingContextID" in target


def _thread_id(target) -> str | None:
    if not isinstance(target, dict):
        return None
    thread = target.get("threadActor")
    if isinstance(thread, dict):
        thread = thread.get("actor")
    if isinstance(thread, str):
        return thread
    return None


def _own_hook(source: str) -> bool:
    return "__obyWatch" in source and "oby-scripts.invalid" in source


def _mark_flag() -> None:
    path = os.environ.get("OBY_PARSED_FLAG")
    if not path:
        return
    try:
        Path(path).write_text("ok\n", encoding="utf-8")
    except OSError as exc:
        _warn(f"oby: could not record that parsed scripts are on: {exc}")


def _warn(message: str) -> None:
    global _warned
    if _warned:
        return
    _warned = True
    print(message, file=sys.stderr)


atexit.register(stop_listener)
