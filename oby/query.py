"""Read the recording while the visit is still running.

Each function reads the live logs in the output folder (flows.jsonl,
ws.jsonl, scripts-parsed.jsonl) and returns plain data. The lists are
summaries. `exchange` and `script` return content, clipped to what was asked
for, and say how long the whole thing is. The whole thing is always on disk.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from oby import initiators
from oby.har import WS_NAME, _read

FLOWS_NAME = "flows.jsonl"
SNIPPET = 80


def _flows(out: Path) -> list[dict]:
    return _read(Path(out) / FLOWS_NAME)


def _header(row: dict, side: str, name: str) -> str:
    for pair in row.get(f"{side}_headers") or []:
        if isinstance(pair, (list, tuple)) and len(pair) >= 2 and str(pair[0]).lower() == name:
            return str(pair[1])
    return ""


def _body(row: dict, side: str) -> dict:
    body = row.get(f"{side}_body")
    return body if isinstance(body, dict) else {}


def _text(row: dict, side: str) -> str:
    body = _body(row, side)
    text = body.get("text")
    return text if isinstance(text, str) and body.get("encoding") != "base64" else ""


def _socket_counts(out: Path) -> dict[str, int]:
    counts: dict[str, int] = {}
    for row in _read(Path(out) / WS_NAME):
        if row.get("closed"):
            continue
        key = str(row.get("id") or "")
        counts[key] = counts.get(key, 0) + 1
    return counts


def summary(index: int, row: dict, sockets: dict[str, int] | None = None) -> dict:
    item = {
        "index": index,
        "method": str(row.get("method") or ""),
        "url": str(row.get("url") or ""),
        "status": row.get("status"),
        "type": _header(row, "response", "content-type"),
        "request_bytes": _body(row, "request").get("bytes", 0),
        "response_bytes": _body(row, "response").get("bytes", 0),
    }
    if row.get("error"):
        item["error"] = str(row["error"])
    count = (sockets or {}).get(str(row.get("id") or ""))
    if count:
        item["websocket_messages"] = count
    return item


def _matches(row: dict, *, host, method, status, contains) -> bool:
    url = str(row.get("url") or "")
    if host and host.lower() not in (urlsplit(url).hostname or "").lower():
        return False
    if method and str(row.get("method") or "").upper() != method.upper():
        return False
    if status is not None and row.get("status") != status:
        return False
    if contains:
        needle = contains.lower()
        hay = (
            url,
            _text(row, "request"),
            _text(row, "response"),
            json.dumps(row.get("request_headers") or []),
            json.dumps(row.get("response_headers") or []),
        )
        if not any(needle in part.lower() for part in hay):
            return False
    return True


def exchanges(
    out: Path,
    *,
    host: str | None = None,
    method: str | None = None,
    status: int | None = None,
    contains: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> dict:
    """Summaries of the exchanges recorded so far, in the order they finished."""
    rows = _flows(out)
    sockets = _socket_counts(out)
    started = initiators.for_folder(out, rows)
    matched = []
    for index, row in enumerate(rows):
        if not _matches(row, host=host, method=method, status=status, contains=contains):
            continue
        item = summary(index, row, sockets)
        if started[index] is not None and "url" in started[index]:
            item["initiator"] = _where(started[index])
        matched.append(item)
    offset = max(0, int(offset))
    limit = max(1, int(limit))
    return {
        "total": len(rows),
        "matched": len(matched),
        "offset": offset,
        "exchanges": matched[offset : offset + limit],
    }


def _where(initiator: dict) -> str:
    """`app.js:12:5 sendSensor`, the frame that made the request."""
    place = f"{initiator.get('url')}:{initiator.get('line')}:{initiator.get('column')}"
    return f"{place} {initiator['function']}" if initiator.get("function") else place


def _clip(body: dict, limit: int) -> dict:
    shown = dict(body)
    text = shown.get("text")
    if isinstance(text, str) and len(text) > limit:
        shown["text"] = text[:limit]
        shown["shown_chars"] = limit
        shown["total_chars"] = len(text)
    return shown


def exchange(out: Path, index: int, *, max_body: int = 20_000) -> dict:
    """One exchange in full: headers in wire order, bodies, timing, preface."""
    rows = _flows(out)
    if not 0 <= index < len(rows):
        return {"error": f"no exchange {index}. {len(rows)} recorded so far."}
    row = dict(rows[index])
    row.pop("request_header_block", None)
    row.pop("response_header_block", None)
    limit = max(0, int(max_body))
    for side in ("request", "response"):
        if isinstance(row.get(f"{side}_body"), dict):
            row[f"{side}_body"] = _clip(row[f"{side}_body"], limit)
    row["index"] = index
    started = initiators.for_folder(out, rows)[index]
    if started is not None:
        row["initiator"] = started
    count = _socket_counts(out).get(str(row.get("id") or ""))
    if count:
        row["websocket_messages"] = count
    return row


def messages(out: Path, index: int, *, offset: int = 0, limit: int = 100, max_chars: int = 4_000) -> dict:
    """The WebSocket messages of one handshake exchange, oldest first."""
    rows = _flows(out)
    if not 0 <= index < len(rows):
        return {"error": f"no exchange {index}. {len(rows)} recorded so far."}
    key = str(rows[index].get("id") or "")
    mine = [row for row in _read(Path(out) / WS_NAME) if key and row.get("id") == key]
    closed = next((row for row in mine if row.get("closed")), None)
    sent = [row for row in mine if not row.get("closed")]
    offset = max(0, int(offset))
    shown = []
    for row in sent[offset : offset + max(1, int(limit))]:
        item = {
            "direction": "send" if row.get("from_client") else "receive",
            "time": row.get("time"),
            "bytes": row.get("bytes", 0),
            "text": row.get("text", ""),
        }
        if row.get("encoding"):
            item["encoding"] = row["encoding"]
        if len(item["text"]) > max_chars:
            item["total_chars"] = len(item["text"])
            item["text"] = item["text"][:max_chars]
        shown.append(item)
    result = {"url": rows[index].get("url"), "total": len(sent), "offset": offset, "messages": shown}
    if closed is not None:
        result["closed"] = {k: closed[k] for k in ("code", "reason", "by_client", "time") if k in closed}
    return result


def _script_items(out: Path) -> list[dict]:
    from oby.scripts import PARSED_NAME, choose_items

    out = Path(out)
    items, _note = choose_items(out / FLOWS_NAME, out / PARSED_NAME)
    return items


def _matcher(needle: str, regex: bool):
    """A function that finds every place `needle` occurs in a text, as (start, end) pairs."""
    import re

    if regex:
        try:
            pattern = re.compile(needle, re.IGNORECASE)
        except re.error as exc:
            raise ValueError(f"that regular expression does not compile: {exc}") from exc
        return lambda text: [match.span() for match in pattern.finditer(text) if match.end() > match.start()]
    lowered = needle.lower()

    def find(text: str) -> list[tuple[int, int]]:
        spans = []
        hay = text.lower()
        at = hay.find(lowered)
        while at != -1:
            spans.append((at, at + len(lowered)))
            at = hay.find(lowered, at + len(lowered))
        return spans

    return find


def _snippets(source: str, find, cap: int = 3) -> tuple[int, list[dict]]:
    spans = find(source)
    found = [
        {"offset": start, "text": source[max(0, start - SNIPPET) : end + SNIPPET]}
        for start, end in spans[:cap]
    ]
    return len(spans), found


def _searchable(item: dict) -> str:
    """What a search looks in: the source, or for a WebAssembly module the names it imports and exports."""
    if item.get("kind") == "wasm":
        names = [f"import {entry['module']}.{entry['name']}" for entry in item.get("imports") or []]
        names += [f"export {entry['name']}" for entry in item.get("exports") or []]
        return "\n".join(names)
    return item.get("source") or ""


def scripts(
    out: Path,
    *,
    contains: str | None = None,
    regex: bool = False,
    kind: str | None = None,
    url: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> dict:
    """The scripts recorded so far, without their source.

    `contains` keeps the scripts whose source has that text, and shows
    where. With `regex` it is a regular expression.
    """
    items = _script_items(out)
    find = _matcher(contains, regex) if contains else None
    matched = []
    for item in items:
        if kind and item.get("kind") != kind:
            continue
        if url and url.lower() not in str(item.get("url") or "").lower():
            continue
        entry = {key: item[key] for key in ("sha256", "kind", "url", "length", "count") if key in item}
        for key in ("introduction", "truncated", "from", "reported"):
            if item.get(key) not in (None, "", False) or (key == "reported" and item.get(key) is False):
                entry[key] = item[key]
        if item.get("kind") == "wasm":
            entry["imports"] = len(item.get("imports") or [])
            entry["exports"] = len(item.get("exports") or [])
        if find:
            count, found = _snippets(_searchable(item), find)
            if not count:
                continue
            entry["matches"] = count
            entry["snippets"] = found
        matched.append(entry)
    offset = max(0, int(offset))
    return {
        "total": len(items),
        "matched": len(matched),
        "offset": offset,
        "scripts": matched[offset : offset + max(1, int(limit))],
    }


def script(
    out: Path,
    sha256: str,
    *,
    offset: int = 0,
    length: int = 20_000,
    view: str = "source",
    find: str | None = None,
    regex: bool = False,
    context: int = 0,
) -> dict:
    """A slice of one script, or the lines in it that match `find`.

    `view` is `source` (as the engine parsed it), `pretty` (reformatted),
    or `deobfuscated` (reformatted, with the obfuscator's spelling undone).
    The other two views are written to scripts/ beside the original the
    first time they are asked for. A sha256 prefix is enough when unique.
    """
    from oby import deob
    from oby.scripts import SCRIPTS_DIR

    out = Path(out)
    wanted = (sha256 or "").strip().lower()
    if not wanted:
        return {"error": "give the sha256 from oby_scripts."}
    found = [item for item in _script_items(out) if str(item.get("sha256", "")).startswith(wanted)]
    distinct = {item["sha256"] for item in found}
    if not distinct:
        return {"error": f"no script with sha256 {wanted}."}
    if len(distinct) > 1:
        return {"error": f"{len(distinct)} scripts start with {wanted}. Give more of the sha256."}
    item = found[0]
    result = {"sha256": item["sha256"], "kind": item.get("kind"), "url": item.get("url")}
    if item.get("kind") == "wasm":
        result.update({key: item[key] for key in ("length", "functions", "imports", "exports", "incomplete") if key in item})
        result["note"] = "A WebAssembly module has no source. Its bytes are in scripts/<sha256>.wasm once the recording is saved."
        return result
    if view not in deob.VIEWS:
        return {"error": f"view is one of {', '.join(deob.VIEWS)}."}
    text, how = deob.view(out / SCRIPTS_DIR, item["sha256"], item.get("source") or "", view)
    result["view"] = view
    result.update(how)
    result["total_chars"] = len(text)
    if find:
        match = _matcher(find, regex)
        lines = text.splitlines()
        hits = []
        total = 0
        context = max(0, min(int(context), 5))
        for number, line in enumerate(lines):
            if not match(line):
                continue
            total += 1
            if len(hits) >= 50:
                continue
            first, last = max(0, number - context), min(len(lines), number + context + 1)
            hits.append({"line": number + 1, "text": "\n".join(part[:400] for part in lines[first:last])})
        result.update({"find": find, "matching_lines": total, "lines": hits})
        return result
    offset = max(0, int(offset))
    result.update({"offset": offset, "source": text[offset : offset + max(1, int(length))]})
    return result


def fingerprint(
    out: Path,
    *,
    api: str | None = None,
    category: str | None = None,
    script: str | None = None,
    limit: int = 50,
) -> dict:
    """Which fingerprinting APIs the page called, most-called first.

    `api`, `category`, and `script` each keep what contains that text.
    Without `api`, each API shows its first three calls.
    """
    from oby import fingerprint as module

    rows = module.read(Path(out) / module.LOG_NAME)
    if not rows:
        return {
            "total": 0,
            "note": "No fingerprint log. Start oby with --fingerprints to record which fingerprinting APIs a page calls.",
        }
    body = module.summary(rows)
    kept = []
    for entry in body["apis"]:
        if api and api.lower() not in entry["api"].lower():
            continue
        if category and category.lower() != entry["category"]:
            continue
        if script and not any(script.lower() in url.lower() for url in entry["scripts"]):
            continue
        shown = dict(entry)
        if not api:
            shown["calls"] = entry["calls"][:3]
        kept.append(shown)
    result = {"total": body["total"], "categories": body["categories"], "apis": kept[: max(1, int(limit))]}
    result["scripts"] = [item for item in body["scripts"] if not script or script.lower() in item["url"].lower()][:20]
    return result


def coverage(out: Path) -> dict:
    """Requests the browser reported against the exchanges on disk."""
    return initiators.coverage(Path(out), _flows(out))


def save(out: Path) -> dict:
    """Write session.har, scripts.json, and scripts/ from what is recorded so far."""
    from oby.har import HAR_NAME, write_har
    from oby.scripts import PARSED_NAME, SCRIPTS_NAME, write_scripts

    out = Path(out)
    entries = write_har(out / FLOWS_NAME, out / HAR_NAME)
    count = write_scripts(out / FLOWS_NAME, out / SCRIPTS_NAME, out / PARSED_NAME)
    result = {"exchanges": entries, "scripts": count}
    from oby import fingerprint as module

    calls = module.write_summary(out)
    if calls is not None:
        result["fingerprint_calls"] = calls
    return result
