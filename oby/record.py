"""mitmproxy addon. Writes one JSON object per completed exchange.

Loaded by mitmdump via `-s`. The output path is `OBY_RECORD`. Bodies are kept
whole. `OBY_MAX_BODY`, when it is a positive number, cuts a body at that many
bytes and marks it truncated. Header order, casing, and repeated names are
kept as pairs. WebSocket messages go to `OBY_WS`, one JSON object per message.
"""

from __future__ import annotations

import base64
import json
import os

# Flow ids already written. The id is the flow's own, not id(flow): Python
# reuses an object's address once it is freed, and a later flow at the same
# address would be taken for one already written and dropped.
_seen: set[str] = set()
# Flows whose request has arrived and whose row is not written yet.
_pending: dict[str, object] = {}
_fp = None
_ws_fp = None
# client connection id -> HTTP/2 preface. mitmproxy strips pseudo-headers
# before they reach flow.request.headers, so the preface is the only copy.
_h2: dict[str, dict] = {}
# How many times we have held a connection open waiting for its HEADERS frame.
_waiting: dict[str, int] = {}
_WAIT_CAP = 4
_WAIT_BYTES = 16384


def _max_body() -> int | None:
    """The body limit in bytes. None keeps every body whole, and is the default."""
    raw = os.environ.get("OBY_MAX_BODY", "")
    try:
        limit = int(raw)
    except ValueError:
        return None
    return limit if limit > 0 else None


# The loopback proxy password rides in this header. mitmproxy removes it before
# the request is forwarded. Keep it out of the recording if a hook order changes.
_LOCAL_AUTH = frozenset({"proxy-authorization", "proxy-authenticate"})


def header_pairs(headers) -> list[list[str]]:
    fields = getattr(headers, "fields", None)
    if fields is not None:
        pairs = fields
    else:
        pairs = headers.items()
    out = []
    for name, value in pairs:
        if isinstance(name, bytes):
            name = name.decode("latin-1")
        if isinstance(value, bytes):
            value = value.decode("latin-1")
        name = str(name)
        if name.lower() in _LOCAL_AUTH:
            continue
        out.append([name, str(value)])
    return out


def header_block(headers) -> str:
    return "".join(f"{name}: {value}\r\n" for name, value in header_pairs(headers))


def body_field(content: bytes | None) -> dict:
    if not content:
        return {"text": None, "truncated": False, "bytes": 0}
    limit = _max_body()
    truncated = limit is not None and len(content) > limit
    chunk = content[:limit] if truncated else content
    try:
        text = chunk.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        text = base64.b64encode(chunk).decode("ascii")
        encoding = "base64"
    return {"text": text, "encoding": encoding, "truncated": truncated, "bytes": len(content)}


def exchange(flow) -> dict:
    request = flow.request
    response = flow.response
    record = {
        "id": str(getattr(flow, "id", "") or ""),
        "url": request.pretty_url,
        "method": request.method,
        "request_http_version": request.http_version,
        "request_headers": header_pairs(request.headers),
        # The raw block, in wire order, including repeated names and original casing.
        "request_header_block": header_block(request.headers),
        "request_body": body_field(request.raw_content if request.raw_content is not None else request.content),
    }
    if response is not None:
        record["status"] = response.status_code
        record["response_http_version"] = response.http_version
        record["response_headers"] = header_pairs(response.headers)
        record["response_header_block"] = header_block(response.headers)
        record["response_body"] = body_field(
            response.raw_content if response.raw_content is not None else response.content
        )
        trailers = getattr(response, "trailers", None)
        if trailers:
            record["response_trailers"] = header_pairs(trailers)
    request_trailers = getattr(request, "trailers", None)
    if request_trailers:
        record["request_trailers"] = header_pairs(request_trailers)
    error = getattr(flow, "error", None)
    if error:
        record["error"] = str(error)
    started = getattr(request, "timestamp_start", None)
    ended = None
    if response is not None:
        ended = getattr(response, "timestamp_end", None)
    if ended is None:
        ended = getattr(request, "timestamp_end", None)
    if isinstance(started, (int, float)):
        record["started"] = started
    if isinstance(ended, (int, float)):
        record["ended"] = ended
    timing = timing_of(flow)
    if timing:
        record["timing"] = timing
    address = _address(getattr(getattr(flow, "server_conn", None), "peername", None))
    if address:
        record["server_address"] = address
    meta = getattr(flow, "metadata", None) or {}
    cloak = meta.get("mitmcloak")
    if cloak is not None:
        record["mitmcloak"] = cloak
    conn = getattr(flow, "client_conn", None)
    conn_id = getattr(conn, "id", None)
    if conn_id is not None and conn_id in _h2:
        record["http2"] = _h2[conn_id]
    return record


def _stamp(source, name: str) -> float | None:
    value = getattr(source, name, None)
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _address(peer) -> str | None:
    if isinstance(peer, (list, tuple)) and peer and isinstance(peer[0], str):
        return peer[0]
    return None


def timing_of(flow) -> dict:
    """Every clock reading mitmproxy took for this exchange, in epoch seconds.

    `client` is the browser's connection to the recorder. `server` is the
    recorder's connection to the origin, which exists only for an exchange
    mitmcloak did not carry (a WebSocket). A mitmcloak exchange has its
    upstream time in the mitmcloak result instead.
    """
    out: dict = {}
    for prefix, source in (("request", getattr(flow, "request", None)), ("response", getattr(flow, "response", None))):
        if source is None:
            continue
        for edge in ("start", "end"):
            value = _stamp(source, f"timestamp_{edge}")
            if value is not None:
                out[f"{prefix}_{edge}"] = value
    for side, names in (
        ("client", ("timestamp_start", "timestamp_tls_setup")),
        ("server", ("timestamp_start", "timestamp_tcp_setup", "timestamp_tls_setup")),
    ):
        conn = getattr(flow, f"{side}_conn", None)
        if conn is None:
            continue
        found = {}
        for name in names:
            value = _stamp(conn, name)
            if value is not None:
                found[name.removeprefix("timestamp_").removesuffix("_setup")] = value
        if found:
            out[side] = found
    return out


def message_row(flow, message) -> dict:
    """One WebSocket message, keyed to its handshake exchange by `id`."""
    content = getattr(message, "content", b"")
    if isinstance(content, str):
        content = content.encode("utf-8")
    content = bytes(content or b"")
    is_text = bool(getattr(message, "is_text", False))
    row = {
        "id": str(getattr(flow, "id", "") or ""),
        "url": getattr(getattr(flow, "request", None), "pretty_url", "") or "",
        "from_client": bool(getattr(message, "from_client", False)),
        "opcode": 1 if is_text else 2,
        "bytes": len(content),
    }
    when = _stamp(message, "timestamp")
    if when is not None:
        row["time"] = when
    if is_text:
        row["text"] = content.decode("utf-8", errors="replace")
    else:
        row["text"] = base64.b64encode(content).decode("ascii")
        row["encoding"] = "base64"
    if getattr(message, "dropped", False):
        row["dropped"] = True
    return row


def close_row(flow) -> dict:
    socket = getattr(flow, "websocket", None)
    row = {
        "id": str(getattr(flow, "id", "") or ""),
        "url": getattr(getattr(flow, "request", None), "pretty_url", "") or "",
        "closed": True,
    }
    for source, dest in (("close_code", "code"), ("close_reason", "reason"), ("closed_by_client", "by_client")):
        value = getattr(socket, source, None)
        if value is not None and value != "":
            row[dest] = value
    when = _stamp(socket, "timestamp_end")
    if when is not None:
        row["time"] = when
    return row


def _open_ws():
    global _ws_fp
    if _ws_fp is None:
        path = os.environ.get("OBY_WS")
        if not path:
            return None
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _ws_fp = open(path, "a", encoding="utf-8")
    return _ws_fp


def _write_ws(row: dict) -> None:
    fp = _open_ws()
    if fp is None:
        return
    fp.write(json.dumps(row, default=str) + "\n")
    fp.flush()


def _open():
    global _fp
    if _fp is None:
        path = os.environ["OBY_RECORD"]
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _fp = open(path, "a", encoding="utf-8")
    return _fp


def _write_stream(entry: dict) -> None:
    """Write a relayed event stream once, with whatever arrived."""
    from oby import stream

    if stream.OPEN.pop(entry["token"], None) is None:
        return
    stream.finish(entry)
    if entry.get("flow") is not None:
        _pending.pop(_key(entry["flow"]), None)
        _seen.add(_key(entry["flow"]))
    row = stream.stream_row(entry, body_field)
    # The request side was copied by the carrier, which does not hold the
    # HTTP/2 prefaces this module captured.
    conn_id = getattr(getattr(entry.get("flow"), "client_conn", None), "id", None)
    if conn_id is not None and conn_id in _h2:
        row["http2"] = _h2[conn_id]
    fp = _open()
    fp.write(json.dumps(row, default=str) + "\n")
    fp.flush()


def _flush_streams() -> None:
    from oby import stream

    for entry in list(stream.OPEN.values()):
        try:
            _write_stream(entry)
        except Exception:
            pass


def _write(flow) -> None:
    token = (getattr(flow, "metadata", None) or {}).get("oby_stream")
    if token:
        from oby import stream

        entry = stream.OPEN.get(token)
        # The relay leg is not a page request. Its row is the stream's.
        if entry is not None and (getattr(flow, "response", None) is not None or getattr(flow, "error", None)):
            _write_stream(entry)
        return
    if getattr(flow, "response", None) is None and not getattr(flow, "error", None):
        return
    _put(flow)


def _key(flow) -> str:
    return str(getattr(flow, "id", None) or id(flow))


def _put(flow, *, unanswered: bool = False) -> None:
    key = _key(flow)
    _pending.pop(key, None)
    if key in _seen:
        return
    _seen.add(key)
    row = exchange(flow)
    if unanswered:
        row["error"] = UNANSWERED
    fp = _open()
    fp.write(json.dumps(row, default=str) + "\n")
    fp.flush()


UNANSWERED = "the session ended before a response arrived"


def _flush_pending() -> None:
    """Write every request still waiting for its response when the session ends."""
    for flow in list(_pending.values()):
        token = (getattr(flow, "metadata", None) or {}).get("oby_stream")
        if token:
            continue
        try:
            _put(flow, unanswered=getattr(flow, "response", None) is None)
        except Exception:
            pass
    _pending.clear()


def _drop_incomplete_preface(conn_id: str) -> None:
    """Let mitmcloak parse the preface again once the HEADERS frame is buffered.

    It keeps the first one it sees, and that one often has settings only.
    """
    try:
        from mitmproxy import ctx

        bridge = ctx.master.addons.get("bridge")
    except Exception:
        return
    profiles = getattr(bridge, "_profiles", None)
    if not isinstance(profiles, dict):
        return
    profile = profiles.get(conn_id)
    preface = getattr(profile, "h2", None)
    if preface is None or getattr(preface, "pseudo_order", None):
        return
    profile.h2 = None
    entries = getattr(getattr(bridge, "catalogue", None), "entries", None)
    stable = getattr(getattr(profile, "hello", None), "stable_id", None)
    if isinstance(entries, dict) and stable in entries:
        entry = entries[stable]
        stale = getattr(entry, "h2", None)
        if stale is not None and not getattr(stale, "pseudo_order", None):
            entry.h2 = None


class _CaptureH2:
    """Runs after mitmproxy's own next_layer addon.

    Script addons are loaded before that addon, so a decision cleared from
    `Record` is put back in the same hook. This one is added once the proxy
    is up, which places it last.
    """

    def next_layer(self, data) -> None:
        try:
            from mitmcloak.capture import parse_h2_preface

            raw = data.data_client()
            preface = parse_h2_preface(raw)
        except Exception:
            return
        if preface is None:
            return
        client = getattr(getattr(data, "context", None), "client", None)
        conn_id = getattr(client, "id", None)
        if not conn_id:
            return
        # ALPN starts the HTTP/2 layer on the first decrypted bytes. A browser
        # often puts SETTINGS in that read and the HEADERS frame in the next,
        # and pseudo-header order lives only in that frame.
        if preface.pseudo_order is None and len(raw) < _WAIT_BYTES:
            waited = _waiting.get(conn_id, 0)
            if waited < _WAIT_CAP:
                _waiting[conn_id] = waited + 1
                data.layer = None
                _drop_incomplete_preface(conn_id)
                return
        _waiting.pop(conn_id, None)
        stored = _h2.get(conn_id)
        if stored and stored.get("pseudo_order"):
            return
        _h2[conn_id] = {
            "settings": [[name, value] for name, value in preface.settings],
            "window_update": preface.window_update,
            "pseudo_order": preface.pseudo_order,
        }


class Record:
    def running(self) -> None:
        from mitmproxy import ctx

        if any(isinstance(addon, _CaptureH2) for addon in ctx.master.addons.chain):
            return
        ctx.master.addons.add(_CaptureH2())

    def requestheaders(self, flow) -> None:
        # Before any addon answers. mitmcloak holds the request hook open for
        # the whole upstream round trip, and a request the session ends on
        # would otherwise leave no row.
        _pending[_key(flow)] = flow

    def request(self, flow) -> None:
        # mitmcloak fills flow.response inside the request hook.
        # Snapshot first. The response hook then widens connect-src for the
        # script report, on the copy the browser receives.
        _write(flow)

    def response(self, flow) -> None:
        _write(flow)

    def error(self, flow) -> None:
        _write(flow)

    def websocket_message(self, flow) -> None:
        socket = getattr(flow, "websocket", None)
        messages = getattr(socket, "messages", None)
        if not messages:
            return
        try:
            _write_ws(message_row(flow, messages[-1]))
        except Exception:
            pass

    def websocket_end(self, flow) -> None:
        try:
            _write_ws(close_row(flow))
        except Exception:
            pass

    def done(self) -> None:
        global _fp, _ws_fp
        # A stream still open when the session ends is written as far as it got.
        _flush_streams()
        _flush_pending()
        if _fp is not None:
            _fp.close()
            _fp = None
        if _ws_fp is not None:
            _ws_fp.close()
            _ws_fp = None


addons = [Record()]
