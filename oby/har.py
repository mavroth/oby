"""Turn the live capture into a HAR 1.2 file.

flows.jsonl is written as each exchange finishes. session.har is written once,
when the session ends. Header order and repeated names stay in the headers
arrays. HTTP/2 preface and the mitmcloak result ride along as `_oby`.

WebSocket messages come from ws.jsonl and sit on their handshake entry as
`_webSocketMessages`, the field Chrome writes. A text/event-stream body is
also split into its events. Each top-level navigation starts a new page.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

HAR_NAME = "session.har"
WS_NAME = "ws.jsonl"
_SKIP = frozenset({"proxy-authorization", "proxy-authenticate"})


def _read(path: Path | None) -> list[dict]:
    rows: list[dict] = []
    if path is None or not path.exists():
        return rows
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def write_har(source: Path, dest: Path, ws: Path | None = None) -> int:
    """Write dest from a JSONL capture. Returns the number of entries.

    WebSocket messages are read from `ws`, which defaults to ws.jsonl beside
    the capture.
    """
    from oby import initiators

    rows = _read(source)
    messages = _read(ws if ws is not None else source.parent / WS_NAME)
    started = initiators.for_folder(source.parent, rows)
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".part")
    with partial.open("w", encoding="utf-8") as handle:
        json.dump(document(rows, messages, started), handle, indent=2)
        handle.write("\n")
    partial.replace(dest)
    return len(rows)


def is_navigation(row: dict) -> bool:
    """A top-level document request, as the browser labels it."""
    dest = mode = ""
    for pair in row.get("request_headers") or []:
        if not isinstance(pair, (list, tuple)) or len(pair) < 2:
            continue
        name = str(pair[0]).lower()
        if name == "sec-fetch-dest":
            dest = str(pair[1]).lower()
        elif name == "sec-fetch-mode":
            mode = str(pair[1]).lower()
    return dest == "document" and mode == "navigate"


def _redirect(row: dict) -> bool:
    status = row.get("status")
    return isinstance(status, int) and 300 <= status < 400


def assign_pages(rows: list[dict]) -> tuple[list[dict], list[str]]:
    """Group exchanges into pages. Returns the pages and one page id per row.

    Everything before the first navigation is page_1, which is the browser's
    own startup traffic. A redirect stays on the page it began, and that page
    takes the URL it ended on.
    """
    pages: list[dict] = []
    refs: list[str] = []
    following = False
    for row in rows:
        url = str(row.get("url") or "")
        started = _iso(row.get("started") if isinstance(row.get("started"), (int, float)) else None)
        navigation = is_navigation(row)
        if navigation and following and pages:
            pages[-1]["title"] = url
        elif not pages or (navigation and refs):
            pages.append(
                {
                    "startedDateTime": started,
                    "id": f"page_{len(pages) + 1}",
                    "title": url or "session",
                    "pageTimings": {},
                }
            )
        elif navigation:
            pages[-1]["title"] = url
        if navigation:
            following = _redirect(row)
        refs.append(pages[-1]["id"])
    if not pages:
        pages.append({"startedDateTime": _iso(None), "id": "page_1", "title": "session", "pageTimings": {}})
    return pages, refs


def group_messages(messages: list[dict] | None) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in messages or []:
        key = row.get("id")
        if isinstance(key, str) and key:
            grouped.setdefault(key, []).append(row)
    return grouped


def document(
    rows: list[dict],
    messages: list[dict] | None = None,
    started: list[dict | None] | None = None,
) -> dict:
    """`started` is one initiator per row, as initiators.match returns."""
    from oby import initiators

    grouped = group_messages(messages)
    pages, refs = assign_pages(rows)
    entries = [
        entry(row, grouped.get(str(row.get("id") or "")), page=ref)
        for row, ref in zip(rows, refs)
    ]
    for built, initiator in zip(entries, started or []):
        if initiator is None:
            continue
        built["_initiator"] = initiators.chrome(initiator)
        built.setdefault("_oby", {})["initiator"] = initiator
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "oby", "version": _version()},
            "pages": pages,
            "entries": entries,
            "_oby": {
                "headers": "wire order, original casing, repeated names",
                "entry": "each entry._oby carries the HTTP/2 preface and mitmcloak result",
                "bodies": "whole, unless an entry._oby says truncated",
                "websocket": "messages are entry._webSocketMessages on the handshake entry",
                "events": "a text/event-stream body is also split into entry._oby.events",
                "timing": "entry._oby.timing holds every clock reading, in epoch seconds",
                "initiator": "entry._oby.initiator is what started the request, as the browser reported it. entry._initiator is the same in Chrome's form",
                "scripts": "scripts.json",
            },
        }
    }


def entry(row: dict, messages: list[dict] | None = None, *, page: str = "page_1") -> dict:
    request_headers = _pairs(row.get("request_headers"))
    response_headers = _pairs(row.get("response_headers"))
    request_body = row.get("request_body") or {}
    response_body = row.get("response_body") or {}
    started = row.get("started")
    ended = row.get("ended")
    timings, total = _timings(started, ended, row.get("timing"))
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
    if isinstance(row.get("timing"), dict) and row["timing"]:
        extra["timing"] = row["timing"]
    for name in ("request_trailers", "response_trailers"):
        trailers = _pairs(row.get(name))
        if trailers:
            extra[name] = _named(trailers)
    if row.get("id"):
        extra["id"] = str(row["id"])
    if _header(response_headers, "content-type").lower().startswith("text/event-stream"):
        text = response_body.get("text")
        if isinstance(text, str) and response_body.get("encoding") != "base64":
            extra["events"] = events(text)
            times = (row.get("stream") or {}).get("event_times") if isinstance(row.get("stream"), dict) else None
            if isinstance(times, list):
                # An event cut off by the end of the stream has no arrival time.
                for item, when in zip(extra["events"], times):
                    item["time"] = when
    if isinstance(row.get("stream"), dict):
        extra["stream"] = {key: value for key, value in row["stream"].items() if key != "event_times"}
    sent, closed = _socket(messages)
    if closed is not None:
        extra["websocket"] = closed
    built = {
        "pageref": page,
        "startedDateTime": _iso(started if isinstance(started, (int, float)) else None),
        "time": total,
        "request": request,
        "response": response,
        "cache": {},
        "timings": timings,
    }
    if isinstance(row.get("server_address"), str) and row["server_address"]:
        built["serverIPAddress"] = row["server_address"]
    if sent is not None:
        built["_resourceType"] = "websocket"
        built["_webSocketMessages"] = sent
    if extra:
        built["_oby"] = extra
    return built


def _socket(messages: list[dict] | None) -> tuple[list[dict] | None, dict | None]:
    """Chrome's _webSocketMessages for one handshake, and how the socket closed."""
    if not messages:
        return None, None
    sent: list[dict] = []
    closed: dict | None = None
    for row in messages:
        if row.get("closed"):
            closed = {key: row[key] for key in ("code", "reason", "by_client", "time") if key in row}
            continue
        item = {
            "type": "send" if row.get("from_client") else "receive",
            "time": row.get("time", 0),
            "opcode": row.get("opcode", 1),
            "data": row.get("text", ""),
        }
        if row.get("encoding") == "base64":
            item["_encoding"] = "base64"
        if row.get("dropped"):
            item["_dropped"] = True
        sent.append(item)
    return sent, closed


def events(text: str) -> list[dict]:
    """Split a text/event-stream body into the events an EventSource delivers."""
    found: list[dict] = []
    current: dict = {}
    data: list[str] = []

    def flush() -> None:
        nonlocal current, data
        if data or current:
            item = dict(current)
            item["data"] = "\n".join(data)
            found.append(item)
        current, data = {}, []

    for line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line == "":
            flush()
            continue
        if line.startswith(":"):
            continue
        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]
        if name == "data":
            data.append(value)
        elif name in ("event", "id", "retry"):
            current[name] = value
    flush()
    return found


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("oby")
    except Exception:
        return "0.2.0"


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


def _ms(later, earlier) -> float | None:
    if not isinstance(later, (int, float)) or not isinstance(earlier, (int, float)):
        return None
    return max(0.0, (later - earlier) * 1000)


def _timings(started, ended, timing=None) -> tuple[dict, float]:
    """HAR timings from the recorder's clock readings.

    send is the browser uploading the request. wait runs from the end of the
    request to the first byte of the response, and for a mitmcloak exchange
    that is the whole upstream round trip. connect and ssl are known only
    when the recorder opened the origin connection for this exchange.
    """
    timing = timing if isinstance(timing, dict) else {}
    send = _ms(timing.get("request_end"), timing.get("request_start"))
    wait = _ms(timing.get("response_start"), timing.get("request_end"))
    receive = _ms(timing.get("response_end"), timing.get("response_start"))
    if send is None or wait is None:
        unknown = {"send": -1, "wait": -1, "receive": -1}
        if not isinstance(started, (int, float)) or not isinstance(ended, (int, float)) or ended < started:
            return unknown, 0
        total = (ended - started) * 1000
        return {"send": 0, "wait": total, "receive": 0}, total
    built: dict = {"blocked": -1, "dns": -1, "connect": -1, "ssl": -1}
    server = timing.get("server") if isinstance(timing.get("server"), dict) else {}
    opened = server.get("start")
    if isinstance(opened, (int, float)) and opened >= timing["request_start"]:
        connect = _ms(server.get("tcp"), opened)
        ssl = _ms(server.get("tls"), server.get("tcp"))
        if connect is not None:
            # HAR counts the TLS handshake inside connect.
            built["connect"] = connect + (ssl or 0)
            if ssl is not None:
                built["ssl"] = ssl
            wait = max(0.0, wait - built["connect"])
    built.update({"send": send, "wait": wait, "receive": receive if receive is not None else 0})
    total = sum(value for key, value in built.items() if key != "ssl" and value > 0)
    return built, total
