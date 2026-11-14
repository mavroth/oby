"""JavaScript that ran during a session.

Firefox's remote debugger reports every script the engine parses, including
fetched files, inline scripts, eval, new Function, string timers, blob
workers, and scripts inserted into the page. That log is preferred.

When the debugger does not start, network files and inline scripts come from
the recorded exchanges, and a hook installed before the page posts eval,
new Function, string timers, and blob workers to a name this recorder answers
itself. The hook is page JavaScript and a site can see it. The collector
exchange is not part of the page recording.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import os
import re
import sys
import threading
from pathlib import Path
from urllib.parse import urlsplit

SINK_HOST = "oby-scripts.invalid"
SINK_URL = f"https://{SINK_HOST}/collect"
SINK_ORIGIN = f"https://{SINK_HOST}"
SCRIPTS_NAME = "scripts.json"
LIVE_NAME = "scripts-live.jsonl"
# mitmdump's save filter. Dots are regex. Keeps the collector out of flows.mitm.
SAVE_FILTER = r"!(~d oby-scripts\.invalid)"

MAX_SOURCE = 500_000
POST_CAP = 2_000
MAX_SCRIPTS = 4_000
DYNAMIC_KINDS = ("eval", "function", "timer", "blob")

HOOK_NOTE = (
    "JavaScript that ran in this session. "
    "The parsed-script listener did not record this visit, so network files and inline scripts are taken from the recording. "
    "eval, new Function, string timers, and blob workers are reported by a hook that runs before the page. "
    "The hook sees calls that go through the global eval, Function, setTimeout, setInterval, Worker, and SharedWorker. "
    "The hook is page JavaScript and a site can see it."
)
PARSED_NOTE = (
    "JavaScript Firefox parsed in this session. "
    "The remote debugger on loopback reported each script, including fetched files, inline scripts, "
    "eval, new Function, string timers, blob workers, dedicated workers, and scripts inserted into the page. "
    "The page was not paused. "
    "zoom.stealth.debugger.force_detach was turned off so the engine would report these scripts. "
    "A page cannot read that preference. Attaching can change how the engine compiles a script."
)
NOTE = HOOK_NOTE

_JS_MIME = {
    "text/javascript",
    "application/javascript",
    "application/x-javascript",
    "text/ecmascript",
    "application/ecmascript",
}
_JS_TYPES = _JS_MIME | {"module"}
_SKIP_TYPES = {
    "application/json",
    "application/ld+json",
    "importmap",
    "speculationrules",
    "text/template",
    "text/html",
    "text/markdown",
    "text/plain",
}
_HTML_MIME = {"text/html", "application/xhtml+xml"}

_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script>", re.IGNORECASE | re.DOTALL)
_TYPE_ATTR = re.compile(r"""\btype\s*=\s*(['"]?)([^'"\s>]+)\1""", re.IGNORECASE)
_SRC_ATTR = re.compile(r"""\bsrc\s*=""", re.IGNORECASE)
_META = re.compile(r"<meta\b[^>]*>", re.IGNORECASE)
_HTTP_EQUIV = re.compile(
    r"""http-equiv\s*=\s*(['"]?)content-security-policy\1""",
    re.IGNORECASE,
)
_CONTENT = re.compile(r"""content\s*=\s*(['"])(.*?)\1""", re.IGNORECASE | re.DOTALL)

_lock = threading.Lock()
_posted = 0
_installed = False
_warned = False

# Tokens are replaced below. The page source stays free of a format string.
_WATCH = r"""
(() => {
  var root = globalThis;
  if (root.__obyWatch) return;
  try {
    Object.defineProperty(root, "__obyWatch", { value: 1, enumerable: false });
  } catch (e) {
    try { root.__obyWatch = 1; } catch (e2) { return; }
  }
  var SINK = __SINK__;
  var LIMIT = __LIMIT__;

  function send(kind, source) {
    try {
      if (typeof source !== "string" || source.length === 0) return;
      var text = source.length > LIMIT ? source.slice(0, LIMIT) : source;
      var body = JSON.stringify({
        kind: kind,
        source: text,
        url: (root.location && root.location.href) || ""
      });
      fetch(SINK, {
        method: "POST",
        mode: "no-cors",
        credentials: "omit",
        cache: "no-store",
        keepalive: true,
        headers: { "content-type": "text/plain" },
        body: body
      }).catch(function () {});
    } catch (e) {}
  }

  function spoof(fn, name) {
    var printed = "function " + name + "() {\n    [native code]\n}";
    var tos = function toString() { return printed; };
    var tosPrinted = "function toString() {\n    [native code]\n}";
    var tosTos = function toString() { return tosPrinted; };
    try { Object.defineProperty(tosTos, "toString", { value: tosTos }); } catch (e) {}
    try { Object.defineProperty(tos, "toString", { value: tosTos }); } catch (e2) {}
    try { Object.defineProperty(fn, "toString", { value: tos }); } catch (e3) {}
    try { Object.defineProperty(fn, "name", { value: name }); } catch (e4) {}
    try { Object.defineProperty(fn, "length", { value: 1 }); } catch (e5) {}
    return fn;
  }

  var blobText = new WeakMap();
  var blobUrls = {};
  var blobUrlCount = 0;

  function rememberBlob(href, text) {
    if (typeof blobUrls[href] === "string") {
      blobUrls[href] = text;
      return;
    }
    if (blobUrlCount >= 200) return;
    blobUrls[href] = text;
    blobUrlCount++;
  }

  function blobSource(seq) {
    if (typeof seq === "string") return seq;
    if (!seq || seq.length == null) return "";
    var bits = [];
    for (var i = 0; i < seq.length; i++) {
      if (typeof seq[i] === "string") bits.push(seq[i]);
    }
    return bits.join("");
  }

  var RealBlob = root.Blob;
  if (typeof RealBlob === "function") {
    var wrappedBlob = spoof(function Blob() {
      var blob = Reflect.construct(RealBlob, arguments, new.target || RealBlob);
      try {
        var text = blobSource(arguments[0]);
        if (text) blobText.set(blob, text);
      } catch (e) {}
      return blob;
    }, "Blob");
    try {
      Object.setPrototypeOf(wrappedBlob, RealBlob);
      wrappedBlob.prototype = RealBlob.prototype;
    } catch (e) {}
    try {
      Object.defineProperty(root, "Blob", { value: wrappedBlob, configurable: true, writable: true });
    } catch (e2) {
      try { root.Blob = wrappedBlob; } catch (e3) {}
    }
  }

  var urlApi = root.URL;
  if (urlApi && typeof urlApi.createObjectURL === "function") {
    var realCreate = urlApi.createObjectURL;
    var wrappedCreate = spoof(function createObjectURL(obj) {
      var href = realCreate.call(urlApi, obj);
      try {
        var text = blobText.get(obj);
        if (typeof text === "string" && String(href).indexOf("blob:") === 0) rememberBlob(String(href), text);
      } catch (e) {}
      return href;
    }, "createObjectURL");
    try {
      Object.defineProperty(urlApi, "createObjectURL", { value: wrappedCreate, configurable: true, writable: true });
    } catch (e) {
      try { urlApi.createObjectURL = wrappedCreate; } catch (e2) {}
    }
  }

  function noteUrl(kind, scriptUrl) {
    try {
      var href = String(scriptUrl && scriptUrl.url ? scriptUrl.url : scriptUrl);
      if (href.indexOf("blob:") === 0) {
        if (typeof blobUrls[href] === "string") {
          send(kind, blobUrls[href]);
          return;
        }
        fetch(href).then(function (r) { return r.text(); }).then(function (t) { send(kind, t); }).catch(function () {});
      } else if (href.indexOf("data:") === 0) {
        var comma = href.indexOf(",");
        var meta = comma >= 0 ? href.slice(0, comma) : "";
        var data = comma >= 0 ? href.slice(comma + 1) : href;
        if (meta.indexOf(";base64") !== -1) {
          try { data = atob(data); } catch (e) {}
        } else {
          try { data = decodeURIComponent(data); } catch (e2) {}
        }
        send(kind, data);
      }
    } catch (e) {}
  }

  var realEval = root.eval;
  var wrappedEval = spoof(function eval(code) {
    if (typeof code === "string") send("eval", code);
    return realEval(code);
  }, "eval");
  try {
    Object.defineProperty(root, "eval", { value: wrappedEval, configurable: true, writable: true });
  } catch (e) {
    try { root.eval = wrappedEval; } catch (e2) {}
  }

  var RealFunction = root.Function;
  var wrappedFunction = spoof(function Function() {
    var parts = [];
    for (var i = 0; i < arguments.length; i++) parts.push(String(arguments[i]));
    send("function", parts.join("\n"));
    return Reflect.construct(RealFunction, arguments, new.target || RealFunction);
  }, "Function");
  try {
    Object.setPrototypeOf(wrappedFunction, RealFunction);
    wrappedFunction.prototype = RealFunction.prototype;
  } catch (e) {}
  try {
    Object.defineProperty(root, "Function", { value: wrappedFunction, configurable: true, writable: true });
  } catch (e2) {
    try { root.Function = wrappedFunction; } catch (e3) {}
  }

  function wrapTimer(name) {
    var real = root[name];
    if (typeof real !== "function") return;
    var wrapped = spoof(function () {
      if (typeof arguments[0] === "string") send("timer", arguments[0]);
      return real.apply(this, arguments);
    }, name);
    try {
      Object.defineProperty(root, name, { value: wrapped, configurable: true, writable: true });
    } catch (e) {}
  }
  wrapTimer("setTimeout");
  wrapTimer("setInterval");

  function wrapCtor(name) {
    var Real = root[name];
    if (typeof Real !== "function") return;
    var wrapped = spoof(function () {
      noteUrl("blob", arguments[0]);
      return Reflect.construct(Real, arguments, new.target || Real);
    }, name);
    try {
      Object.setPrototypeOf(wrapped, Real);
      wrapped.prototype = Real.prototype;
    } catch (e) {}
    try {
      Object.defineProperty(root, name, { value: wrapped, configurable: true, writable: true });
    } catch (e2) {
      try { root[name] = wrapped; } catch (e3) {}
    }
  }
  wrapCtor("Worker");
  wrapCtor("SharedWorker");
})();
"""

WATCH_SOURCE = _WATCH.replace("__SINK__", json.dumps(SINK_URL)).replace("__LIMIT__", str(MAX_SOURCE))


def is_sink_host(host: str) -> bool:
    name = host.lower().strip()
    if name.startswith("["):
        return False
    return name.split(":", 1)[0] == SINK_HOST


def is_sink_url(url: str) -> bool:
    try:
        return (urlsplit(url).hostname or "").lower() == SINK_HOST
    except ValueError:
        return False


def is_sink_flow(flow) -> bool:
    request = getattr(flow, "request", None)
    if request is None:
        return False
    host = getattr(request, "host", None)
    if isinstance(host, bytes):
        host = host.decode("latin-1", "replace")
    if host and is_sink_host(str(host)):
        return True
    return is_sink_url(str(getattr(request, "pretty_url", None) or ""))


def clip(source: str) -> tuple[str, bool]:
    if len(source) > MAX_SOURCE:
        return source[:MAX_SOURCE], True
    return source, False


def append_report(raw: bytes, dest: str | None = None) -> None:
    """Store one hook report. The path defaults to OBY_SCRIPTS."""
    global _posted
    if not raw:
        return
    path = dest or os.environ.get("OBY_SCRIPTS")
    if not path:
        return
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return
    if not isinstance(payload, dict):
        return
    source = payload.get("source")
    if not isinstance(source, str) or source == "":
        return
    kind = payload.get("kind")
    if kind not in DYNAMIC_KINDS:
        kind = "eval"
    source, truncated = clip(source)
    url = payload.get("url")
    if not isinstance(url, str):
        url = ""
    line = {"kind": kind, "source": source, "url": url[:2048]}
    if truncated:
        line["truncated"] = True
    with _lock:
        if _posted >= POST_CAP:
            return
        _posted += 1
        folder = os.path.dirname(path)
        if folder:
            os.makedirs(folder, exist_ok=True)
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(line, ensure_ascii=False) + "\n")
            handle.flush()


def answer_sink(flow) -> bool:
    """Reply to the collector and keep the body off the upstream proxy.

    mitmcloak returns immediately when a response is already set, so this has
    to run in an addon loaded before it.
    """
    if not is_sink_flow(flow):
        return False
    if getattr(flow, "response", None) is None:
        request = getattr(flow, "request", None)
        method = str(getattr(request, "method", "") or "").upper()
        if method == "POST" and request is not None:
            raw = getattr(request, "raw_content", None)
            if raw is None:
                raw = getattr(request, "content", None)
            if raw:
                try:
                    append_report(raw)
                except Exception:
                    pass
        try:
            from mitmproxy import http

            flow.response = http.Response.make(
                204,
                b"",
                {
                    "Access-Control-Allow-Origin": "*",
                    "Cache-Control": "no-store",
                },
            )
        except Exception:
            return False
    return True


def relax_policy(policy: str) -> str:
    """Let the page post the hook report. Other directives stay as the site sent them."""
    chunks = []
    for part in policy.split(";"):
        part = part.strip()
        if part:
            chunks.append(part.split())
    if not chunks:
        return policy
    names = [chunk[0].lower() for chunk in chunks if chunk]
    if "connect-src" in names:
        index = names.index("connect-src")
        chunks[index] = _with_origin(chunks[index])
    elif "default-src" in names:
        index = names.index("default-src")
        chunks.append(_with_origin(["connect-src", *chunks[index][1:]]))
    else:
        return policy
    return "; ".join(" ".join(chunk) for chunk in chunks)


def _with_origin(tokens: list[str]) -> list[str]:
    if any(token.lower() == SINK_ORIGIN.lower() for token in tokens):
        return tokens
    body = [token for token in tokens[1:] if token.lower() not in {"'none'", "none"}]
    return [tokens[0], *body, SINK_ORIGIN]


def patch_html(text: str) -> str:
    """Add the collector to a meta Content-Security-Policy, when the page has one."""

    def repl(match: re.Match) -> str:
        tag = match.group(0)
        if not _HTTP_EQUIV.search(tag):
            return tag

        def content_repl(inner: re.Match) -> str:
            quote = inner.group(1)
            return f"content={quote}{relax_policy(inner.group(2))}{quote}"

        return _CONTENT.sub(content_repl, tag, count=1)

    return _META.sub(repl, text)


def parsed_debugger_ready() -> bool:
    """True once the parsed-script listener is attached for this process."""
    flag = os.environ.get("OBY_PARSED_FLAG")
    return bool(flag) and os.path.exists(flag)


def allow_script_report(flow) -> None:
    """Widen connect-src on the copy the browser receives.

    Call this after the exchange has been snapshotted. The saved header stays
    the one the site sent. A meta policy is patched the same way. The parsed
    script listener does not need this, so a live debugger leaves the policy.
    """
    if parsed_debugger_ready() or is_sink_flow(flow):
        return
    response = getattr(flow, "response", None)
    if response is None:
        return
    headers = getattr(response, "headers", None)
    if headers is not None and hasattr(headers, "get_all") and hasattr(headers, "set_all"):
        values = headers.get_all("content-security-policy")
        if values:
            headers.set_all("content-security-policy", [relax_policy(value) for value in values])
    if headers is None or not hasattr(headers, "get"):
        return
    if "html" not in str(headers.get("content-type", "") or "").lower():
        return
    raw = getattr(response, "content", None)
    if not raw:
        return
    try:
        text = raw.decode("utf-8")
    except (AttributeError, UnicodeDecodeError):
        return
    patched = patch_html(text)
    if patched != text:
        response.content = patched.encode("utf-8")


def inline_scripts(html: str) -> list[str]:
    found = []
    for attrs, body in _SCRIPT_RE.findall(html):
        if _SRC_ATTR.search(attrs):
            continue
        typed = _TYPE_ATTR.search(attrs)
        if typed is not None:
            kind = typed.group(2).lower().split(";", 1)[0].strip()
            if kind in _SKIP_TYPES or kind not in _JS_TYPES:
                continue
        if not body.strip():
            continue
        found.append(body)
    return found


def is_javascript(url: str, content_type: str) -> bool:
    mime = content_type.split(";", 1)[0].strip().lower()
    if mime in _HTML_MIME or mime in _SKIP_TYPES:
        return False
    if mime in _JS_MIME or "javascript" in mime or "ecmascript" in mime:
        return True
    if mime and mime not in {"application/octet-stream", "text/plain"}:
        return False
    path = urlsplit(url).path.lower()
    return path.endswith(".js") or path.endswith(".mjs")


def is_html(content_type: str) -> bool:
    return content_type.split(";", 1)[0].strip().lower() in _HTML_MIME


def _content_type(headers) -> str:
    if not isinstance(headers, list):
        return ""
    for item in headers:
        if isinstance(item, (list, tuple)) and len(item) >= 2 and str(item[0]).lower() == "content-type":
            return str(item[1])
    return ""


def _body_text(body: dict) -> str | None:
    text = body.get("text")
    if not isinstance(text, str):
        return None
    if body.get("encoding") == "base64":
        try:
            return base64.b64decode(text).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return None
    return text


def make_item(kind: str, url: str, source: str, truncated: bool, *, limit: bool = True) -> dict:
    # The debugger text is the engine's copy, so a vendor bundle stays whole.
    # The wire body and the page hook stay on MAX_SOURCE.
    if limit:
        source, cut = clip(source)
    else:
        cut = False
    item = {
        "kind": kind,
        "url": url,
        "sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "length": len(source),
        "count": 1,
        "source": source,
    }
    if truncated or cut:
        item["truncated"] = True
    return item


def from_exchange(row: dict) -> list[dict]:
    url = str(row.get("url") or "")
    if is_sink_url(url):
        return []
    response = row.get("response_body")
    if not isinstance(response, dict):
        return []
    text = _body_text(response)
    if text is None:
        return []
    ctype = _content_type(row.get("response_headers"))
    truncated = bool(response.get("truncated"))
    items = []
    if is_javascript(url, ctype):
        items.append(make_item("network", url, text, truncated))
    if is_html(ctype):
        items.extend(make_item("inline", url, source, truncated) for source in inline_scripts(text))
    return items


def from_parsed(row: dict) -> dict | None:
    source = row.get("source")
    if not isinstance(source, str) or source == "":
        return None
    kind = row.get("kind")
    if kind not in {"network", "inline", *DYNAMIC_KINDS}:
        kind = "inline"
    url = row.get("url") if isinstance(row.get("url"), str) else ""
    item = make_item(kind, url[:2048], source, bool(row.get("truncated")), limit=False)
    introduction = row.get("introduction")
    if isinstance(introduction, str) and introduction:
        item["introduction"] = introduction
    return item


def from_report(row: dict) -> dict | None:
    source = row.get("source")
    if not isinstance(source, str) or source == "":
        return None
    kind = row.get("kind")
    if kind not in DYNAMIC_KINDS:
        kind = "eval"
    url = row.get("url") if isinstance(row.get("url"), str) else ""
    return make_item(kind, url[:2048], source, bool(row.get("truncated")))


def _rows(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def gather(flows: Path, live: Path) -> list[dict]:
    items: list[dict] = []
    for row in _rows(flows):
        items.extend(from_exchange(row))
    for row in _rows(live):
        item = from_report(row)
        if item is not None:
            items.append(item)
    return _dedupe(items)


def _dedupe(items: list[dict]) -> list[dict]:
    order: list[dict] = []
    index: dict[tuple, int] = {}
    for item in items:
        key = (item["kind"], item["sha256"], item["url"])
        if key in index:
            slot = order[index[key]]
            slot["count"] += item["count"]
            if item.get("truncated"):
                slot["truncated"] = True
            continue
        index[key] = len(order)
        order.append(item)
    return order


def counts_of(items: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        counts[item["kind"]] = counts.get(item["kind"], 0) + int(item["count"])
    return counts


def document(items: list[dict], *, note: str = NOTE) -> dict:
    truncated = len(items) > MAX_SCRIPTS
    kept = items[:MAX_SCRIPTS]
    body = {
        "version": 1,
        "note": note,
        "counts": counts_of(kept),
        "scripts": kept,
    }
    if truncated:
        body["truncated"] = True
    return body


def choose_items(flows: Path, live: Path, parsed: Path | None = None) -> tuple[list[dict], str]:
    """Prefer the engine's parsed scripts. The hook list is the fallback."""
    if parsed is not None and parsed.is_file() and parsed.stat().st_size > 0:
        items = []
        for row in _rows(parsed):
            item = from_parsed(row)
            if item is not None:
                items.append(item)
        return _dedupe(items), PARSED_NOTE
    return gather(flows, live), HOOK_NOTE


def write_scripts(flows: Path, live: Path, dest: Path, parsed: Path | None = None) -> int:
    """Write dest from parsed scripts, or from the capture and the hook. Returns how many."""
    items, note = choose_items(flows, live, parsed)
    body = document(items, note=note)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    return len(body["scripts"])


def write_session_scripts(out: Path, flows: Path, live: Path) -> None:
    from oby.parsed import PARSED_NAME, stop_listener

    stop_listener()
    try:
        write_scripts(flows, live, out / SCRIPTS_NAME, out / PARSED_NAME)
    except Exception as exc:
        print(f"oby: could not write {SCRIPTS_NAME}: {exc}", file=sys.stderr)


def progress(flows: Path, live: Path, parsed: Path | None = None) -> dict:
    """Counts only. Script source stays in the session folder."""
    try:
        items, _note = choose_items(flows, live, parsed)
    except Exception:
        items = []
    counts = counts_of(items)
    return {"total": sum(counts.values()), "by_kind": counts}


def install_script_watcher() -> None:
    """Listen for parsed scripts, and keep the page hook when that listener fails."""
    global _installed
    if _installed:
        return
    from invisible_playwright.async_api import InvisiblePlaywright as AsyncPW
    from invisible_playwright.launcher import InvisiblePlaywright as SyncPW

    from oby.parsed import install_on

    install_on(SyncPW, AsyncPW)
    _wrap_enter(SyncPW, "__enter__", awaitable=False)
    _wrap_enter(AsyncPW, "__aenter__", awaitable=True)
    _installed = True


def _wrap_enter(cls, name: str, *, awaitable: bool) -> None:
    original = getattr(cls, name)
    if getattr(original, "_oby_scripts", False):
        return
    if awaitable:

        async def wrapped(self, *args, **kwargs):
            result = await original(self, *args, **kwargs)
            if not _debugger_ready(self):
                await _arm(result)
            else:
                _arm_navigation(result)
            return result
    else:

        def wrapped(self, *args, **kwargs):
            result = original(self, *args, **kwargs)
            if not _debugger_ready(self):
                _arm_sync(result)
            else:
                _arm_navigation(result)
            return result

    wrapped._oby_scripts = True  # type: ignore[attr-defined]
    setattr(cls, name, wrapped)


def _arm_sync(result) -> None:
    add = _adder(result)
    if add is None:
        _wrap_new_context(result, awaitable=False)
        return
    try:
        handle = add(WATCH_SOURCE)
    except Exception as exc:
        _warn(exc)
        return
    if inspect.isawaitable(handle):
        handle.close()
        _warn(RuntimeError("the sync browser returned an awaitable init script"))
        return
    _remember(result, handle)


async def _arm(result) -> None:
    add = _adder(result)
    if add is None:
        _wrap_new_context(result, awaitable=True)
        return
    try:
        handle = add(WATCH_SOURCE)
        if inspect.isawaitable(handle):
            handle = await handle
    except Exception as exc:
        _warn(exc)
        return
    _remember(result, handle)


def _adder(result):
    if getattr(result, "_oby_script_handle", None) is not None:
        return None
    add = getattr(result, "add_init_script", None)
    if not callable(add):
        return None
    return add


def _remember(result, handle) -> None:
    try:
        setattr(result, "_oby_script_handle", handle)
    except Exception:
        pass


def _wrap_new_context(result, *, awaitable: bool) -> None:
    new_context = getattr(result, "new_context", None)
    if not callable(new_context) or getattr(new_context, "_oby_scripts", False):
        return
    if awaitable:

        async def wrapped(*args, **kwargs):
            ctx = await new_context(*args, **kwargs)
            await _arm(ctx)
            return ctx
    else:

        def wrapped(*args, **kwargs):
            ctx = new_context(*args, **kwargs)
            _arm_sync(ctx)
            return ctx

    wrapped._oby_scripts = True  # type: ignore[attr-defined]
    try:
        result.new_context = wrapped
    except Exception:
        pass


def _arm_navigation(result) -> None:
    try:
        from oby.parsed import arm_navigation

        arm_navigation(result)
    except Exception as exc:
        _warn(exc)


def _debugger_ready(launcher) -> bool:
    try:
        from oby.parsed import start_parsed

        return bool(start_parsed(launcher))
    except Exception as exc:
        _warn(exc)
        return False


def _warn(exc: BaseException) -> None:
    global _warned
    if _warned:
        return
    _warned = True
    print(f"oby: could not install the script watcher: {exc}", file=sys.stderr)
