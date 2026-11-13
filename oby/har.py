"""Turn the live capture into a HAR 1.2 file.

flows.jsonl is written as each exchange finishes. session.har is written once,
when the session ends. Header order and repeated names stay in the headers
arrays. HTTP/2 preface and the mitmcloak result ride along as `_oby`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

HAR_NAME = "session.har"
_SKIP = frozenset({"proxy-authorization", "proxy-authenticate"})


def write_har(source: Path, dest: Path) -> int:
    """Write dest from a JSONL capture. Returns the number of entries."""
    rows: list[dict] = []
    if source.exists():
        for line in source.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(document(rows), indent=2) + "\n", encoding="utf-8")
    return len(rows)


def document(rows: list[dict]) -> dict:
    entries = [entry(row) for row in rows]
    started = entries[0]["startedDateTime"] if entries else _iso(None)
    page = str((rows[0].get("url") if rows else "") or "session")
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "oby", "version": _version()},
            "pages": [
                {
                    "startedDateTime": started,
                    "id": "page_1",
                    "title": page,
                    "pageTimings": {},
                }
            ],
            "entries": entries,
            "_oby": {
                "headers": "wire order, original casing, repeated names",
                "entry": "each entry._oby carries the HTTP/2 preface and mitmcloak result",
                "scripts": "scripts.json lists the JavaScript that ran. The collector exchange is not an entry.",
            },
        }
    }


def entry(row: dict) -> dict:
    request_headers = _pairs(row.get("request_headers"))
    response_headers = _pairs(row.get("response_headers"))
    request_body = row.get("request_body") or {}
    response_body = row.get("response_body") or {}
    started = row.get("started")
    ended = row.get("ended")
    timings, total = _timings(started, ended)
    request = {
        "method": str(row.get("method") or "GET"),
        "url": str(row.get("url") or ""),
        "httpVersion": str(row.get("request_http_version") or ""),
        "cookies": _request_cookies(request_headers),
        "headers": _named(request_headers),
        "queryString": _query(str(row.get("url") or "")),
        "headersSize": _block_size(row.get("request_header_block")),
        "bodySize": _body_size(request_body),
    }
    posted = _post(request_headers, request_body)
    if posted is not None:
        request["postData"] = posted
    location = _header(response_headers, "location")
    response = {
        "status": int(row["status"]) if row.get("status") is not None else 0,
        "statusText": str(row.get("error") or ""),
        "httpVersion": str(row.get("response_http_version") or ""),
        "cookies": _response_cookies(response_headers),
        "headers": _named(response_headers),
        "content": _content(response_headers, response_body),
        "redirectURL": location,
        "headersSize": _block_size(row.get("response_header_block")),
        "bodySize": _body_size(response_body),
    }
    extra = {}
    if row.get("http2") is not None:
        extra["http2"] = row["http2"]
    if row.get("mitmcloak") is not None:
        extra["mitmcloak"] = row["mitmcloak"]
    if request_body.get("truncated") or response_body.get("truncated"):
        extra["truncated"] = True
    built = {
        "pageref": "page_1",
        "startedDateTime": _iso(started if isinstance(started, (int, float)) else None),
        "time": total,
        "request": request,
        "response": response,
        "cache": {},
        "timings": timings,
    }
    if extra:
        built["_oby"] = extra
    return built


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("oby")
    except Exception:
        return "0.1.0"


def _pairs(value) -> list[list[str]]:
    if not isinstance(value, list):
        return []
    pairs = []
    for item in value:
        if not isinstance(item, (list, tuple)) or len(item) < 2:
            continue
        name, raw = str(item[0]), str(item[1])
        if name.lower() in _SKIP:
            continue
        pairs.append([name, raw])
    return pairs


def _named(pairs: list[list[str]]) -> list[dict[str, str]]:
    return [{"name": name, "value": value} for name, value in pairs]


def _header(pairs: list[list[str]], name: str) -> str:
    for key, value in pairs:
        if key.lower() == name:
            return value
    return ""


def _query(url: str) -> list[dict[str, str]]:
    query = urlsplit(url).query
    return [{"name": name, "value": value} for name, value in parse_qsl(query, keep_blank_values=True)]


def _request_cookies(pairs: list[list[str]]) -> list[dict[str, str]]:
    found = []
    for name, value in pairs:
        if name.lower() != "cookie":
            continue
        for piece in value.split(";"):
            piece = piece.strip()
            if not piece:
                continue
            cookie_name, _, cookie_value = piece.partition("=")
            found.append({"name": cookie_name.strip(), "value": cookie_value})
    return found


def _response_cookies(pairs: list[list[str]]) -> list[dict]:
    found = []
    for name, value in pairs:
        if name.lower() != "set-cookie":
            continue
        parts = [part.strip() for part in value.split(";") if part.strip()]
        if not parts:
            continue
        cookie_name, _, cookie_value = parts[0].partition("=")
        cookie: dict = {"name": cookie_name, "value": cookie_value}
        for attr in parts[1:]:
            key, _, attr_value = attr.partition("=")
            flag = key.lower()
            if flag == "path":
                cookie["path"] = attr_value
            elif flag == "domain":
                cookie["domain"] = attr_value
            elif flag == "expires":
                cookie["expires"] = attr_value
            elif flag == "httponly":
                cookie["httpOnly"] = True
            elif flag == "secure":
                cookie["secure"] = True
        found.append(cookie)
    return found


def _post(pairs: list[list[str]], body: dict) -> dict | None:
    text = body.get("text")
    if text is None:
        return None
    posted = {"mimeType": _header(pairs, "content-type"), "text": text}
    if body.get("encoding") == "base64":
        posted["_encoding"] = "base64"
    return posted


def _content(pairs: list[list[str]], body: dict) -> dict:
    content: dict = {
        "size": _body_size(body),
        "mimeType": _header(pairs, "content-type"),
    }
    text = body.get("text")
    if text is not None:
        content["text"] = text
    if body.get("encoding") == "base64":
        content["encoding"] = "base64"
    return content


def _body_size(body: dict) -> int:
    try:
        return int(body.get("bytes", 0))
    except (TypeError, ValueError):
        return 0


def _block_size(block) -> int:
    if not isinstance(block, str) or not block:
        return -1
    return len(block.encode("latin-1", errors="replace"))


def _iso(ts: float | None) -> str:
    when = datetime.fromtimestamp(ts, timezone.utc) if ts is not None else datetime.now(timezone.utc)
    return when.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _timings(started, ended) -> tuple[dict, float]:
    unknown = {"send": -1, "wait": -1, "receive": -1}
    if not isinstance(started, (int, float)) or not isinstance(ended, (int, float)) or ended < started:
        return unknown, 0
    total = (ended - started) * 1000
    return {"send": 0, "wait": total, "receive": 0}, total
