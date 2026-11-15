"""JavaScript that ran during a session.

The DevTools watch in chrome.py reads every script V8 parses, including
fetched files, inline scripts, eval, new Function, string timers, and blob
workers, and writes them to scripts-parsed.jsonl. That log is the list.

A fetched file or an inline script whose text the watch did not get is read
back from the recorded exchange. When the watch did not attach at all, the
list is the fetched files and inline scripts in the recording.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit

SCRIPTS_NAME = "scripts.json"
PARSED_NAME = "scripts-parsed.jsonl"
SCRIPTS_DIR = "scripts"
# No limit on a script's length or on how many are listed. A number here
# cuts at that point and marks the result truncated.
MAX_SOURCE: int | None = None
MAX_SCRIPTS: int | None = None
DYNAMIC_KINDS = ("eval", "function", "timer", "blob")

WIRE_NOTE = (
    "JavaScript in this session's recording. "
    "The DevTools watch did not attach, so this is the fetched files and inline scripts in the recorded responses. "
    "eval, new Function, string timers, and blob workers are not listed."
)
PARSED_NOTE = (
    "JavaScript Chrome parsed in this session. "
    "A DevTools client on loopback read each script from V8 as it was parsed, including fetched files, inline scripts, "
    "eval, new Function, string timers, blob workers, and workers. "
    "Nothing was injected into the page and the page was not paused. "
    "new Function is told from eval by its source. A string timer is listed as eval."
)
NOTE = PARSED_NOTE

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
def clip(source: str) -> tuple[str, bool]:
    if MAX_SOURCE and len(source) > MAX_SOURCE:
        return source[:MAX_SOURCE], True
    return source, False


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
    # The wire body is whole too unless MAX_SOURCE is set.
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


def gather(flows: Path) -> list[dict]:
    items: list[dict] = []
    for row in _rows(flows):
        items.extend(from_exchange(row))
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
    truncated = bool(MAX_SCRIPTS) and len(items) > MAX_SCRIPTS
    kept = items[:MAX_SCRIPTS] if truncated else items
    body = {
        "version": 1,
        "note": note,
        "counts": counts_of(kept),
        "scripts": kept,
    }
    if truncated:
        body["truncated"] = True
    return body


def choose_items(flows: Path, parsed: Path | None = None) -> tuple[list[dict], str]:
    """The engine's parsed scripts. The recording alone is the fallback."""
    if parsed is not None and parsed.is_file() and parsed.stat().st_size > 0:
        items = []
        for row in _rows(parsed):
            item = from_parsed(row)
            if item is not None:
                items.append(item)
        unfetched = [row for row in _rows(parsed) if row.get("unfetched")]
        # A file whose text was cut off part way is owed in the same way.
        cut = [item for item in items if item["kind"] == "network" and item.get("truncated")]
        whole = [item for item in items if item not in cut]
        filled = wire_fill(whole, unfetched + cut, flows)
        found = {item["url"] for item in filled}
        kept = whole + [item for item in cut if item["url"] not in found]
        asked = script_requests(kept + filled, flows)
        return _dedupe(kept + filled + asked), PARSED_NOTE
    return gather(flows), WIRE_NOTE


def wire_fill(parsed: list[dict], unfetched: list[dict], flows: Path) -> list[dict]:
    """Scripts the engine parsed whose text the watch did not get in time.

    The engine names each script as it is parsed and gives the text on
    request. A page that closes first takes the unanswered texts with it,
    and the watch then records the name alone. A fetched file is in the
    recording either way, so its text is taken from there and the item says
    `from: wire`. Only a script the debugger named is filled here.
    script_requests adds a file that was fetched to run and never named.
    """
    have = {(item["kind"], item["url"]) for item in parsed}
    wanted = {
        (row["kind"], row["url"])
        for row in unfetched
        if isinstance(row.get("url"), str)
        and row.get("kind") in ("network", "inline")
        and (row["kind"], row["url"]) not in have
    }
    if not wanted:
        return []
    urls = {url for _kind, url in wanted}
    filled: list[dict] = []
    for row in _rows(flows):
        if row.get("url") not in urls:
            continue
        for item in from_exchange(row):
            # A document's inline scripts all share its URL, so all are taken.
            if (item["kind"], item["url"]) in wanted:
                item["from"] = "wire"
                filled.append(item)
        urls.discard(row.get("url"))
    return filled


# What the browser puts in Sec-Fetch-Dest when the response is going to be run.
_RUN_DESTS = frozenset({"script", "worker", "sharedworker", "serviceworker", "audioworklet", "paintworklet"})


def script_requests(have: list[dict], flows: Path) -> list[dict]:
    """Files the browser fetched to run that the engine never named.

    The watch can miss a script: one that arrives as the page is leaving,
    or one in a thread it had not attached to yet. The request still says
    what the file was for. A browser sends Sec-Fetch-Dest: script only for a
    script element, a module import, or a script preload, so a 200 answer
    to it is JavaScript the page asked to run. The item says `from: wire`
    and `reported: false`, because the engine did not confirm it was
    parsed. A preload the page never used is the one case where it was not.
    """
    known = {item["url"] for item in have if item["kind"] == "network"}
    added: list[dict] = []
    for row in _rows(flows):
        url = row.get("url")
        if not isinstance(url, str) or url in known or row.get("status") != 200:
            continue
        dest = ""
        for pair in row.get("request_headers") or []:
            if isinstance(pair, (list, tuple)) and len(pair) == 2 and str(pair[0]).lower() == "sec-fetch-dest":
                dest = str(pair[1]).strip().lower()
        if dest not in _RUN_DESTS:
            continue
        for item in from_exchange(row):
            if item["kind"] == "network":
                item["from"] = "wire"
                item["reported"] = False
                added.append(item)
                known.add(url)
    return added


def write_scripts(flows: Path, dest: Path, parsed: Path | None = None) -> int:
    """Write dest from the parsed scripts, or from the recording alone. Returns how many."""
    items, note = choose_items(flows, parsed)
    body = document(items, note=note)
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        write_script_files(body["scripts"], dest.parent / SCRIPTS_DIR)
        body["files"] = f"{SCRIPTS_DIR}/<sha256>.js holds each script's source on its own"
    except OSError as exc:
        print(f"oby: could not write {SCRIPTS_DIR}/: {exc}", file=sys.stderr)
    partial = dest.with_name(dest.name + ".part")
    partial.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    partial.replace(dest)
    return len(body["scripts"])


def write_script_files(items: list[dict], folder: Path) -> int:
    """Write each distinct source to folder/<sha256>.js, and name it on the item.

    scripts.json keeps the source as well. The files are for grep, a
    formatter, or a diff, which read a file and not a JSON string.
    """
    folder.mkdir(parents=True, exist_ok=True)
    written = 0
    for item in items:
        digest = item.get("sha256")
        source = item.get("source")
        if not isinstance(digest, str) or not isinstance(source, str):
            continue
        path = folder / f"{digest}.js"
        item["file"] = f"{folder.name}/{path.name}"
        if path.exists():
            continue
        path.write_text(source, encoding="utf-8", errors="surrogatepass")
        written += 1
    return written


def write_session_scripts(out: Path, flows: Path) -> None:
    from oby.chrome import stop_watch

    stop_watch()
    try:
        write_scripts(flows, out / SCRIPTS_NAME, out / PARSED_NAME)
    except Exception as exc:
        print(f"oby: could not write {SCRIPTS_NAME}: {exc}", file=sys.stderr)


def progress(flows: Path, parsed: Path | None = None) -> dict:
    """Counts only. Script source stays in the session folder."""
    try:
        items, _note = choose_items(flows, parsed)
    except Exception:
        items = []
    counts = counts_of(items)
    return {"total": sum(counts.values()), "by_kind": counts}
