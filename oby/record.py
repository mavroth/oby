"""mitmproxy addon. Writes one JSON object per completed exchange.

Loaded by mitmdump via `-s`. The output path is `OBY_RECORD`. Bodies larger
than `OBY_MAX_BODY` bytes are cut and marked truncated. Header order, casing,
and repeated names are kept as pairs.
"""

from __future__ import annotations

import base64
import json
import os

from oby.scripts import allow_script_report, is_sink_flow

_seen: set[int] = set()
_fp = None
# client connection id -> HTTP/2 preface. mitmproxy strips pseudo-headers
# before they reach flow.request.headers, so the preface is the only copy.
_h2: dict[str, dict] = {}
# How many times we have held a connection open waiting for its HEADERS frame.
_waiting: dict[str, int] = {}
_WAIT_CAP = 4
_WAIT_BYTES = 16384


def _max_body() -> int:
    raw = os.environ.get("OBY_MAX_BODY", "1000000")
    try:
        return max(0, int(raw))
    except ValueError:
        return 1_000_000


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
    truncated = len(content) > limit
    chunk = content[:limit]
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
    meta = getattr(flow, "metadata", None) or {}
    cloak = meta.get("mitmcloak")
    if cloak is not None:
        record["mitmcloak"] = cloak
    conn = getattr(flow, "client_conn", None)
    conn_id = getattr(conn, "id", None)
    if conn_id is not None and conn_id in _h2:
        record["http2"] = _h2[conn_id]
    return record


def _open():
    global _fp
    if _fp is None:
        path = os.environ["OBY_RECORD"]
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        _fp = open(path, "a", encoding="utf-8")
    return _fp


def _write(flow) -> None:
    # The script hook posts here. It is not a page request.
    if is_sink_flow(flow):
        return
    if getattr(flow, "response", None) is None and not getattr(flow, "error", None):
        return
    key = id(flow)
    if key in _seen:
        return
    _seen.add(key)
    fp = _open()
    fp.write(json.dumps(exchange(flow), default=str) + "\n")
    fp.flush()


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
        # ALPN starts the HTTP/2 layer on the first decrypted bytes. Firefox
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

    def request(self, flow) -> None:
        # mitmcloak fills flow.response inside the request hook.
        # Snapshot first. The response hook then widens connect-src for the
        # script report, on the copy the browser receives.
        _write(flow)

    def response(self, flow) -> None:
        _write(flow)
        try:
            allow_script_report(flow)
        except Exception:
            pass

    def error(self, flow) -> None:
        _write(flow)

    def done(self) -> None:
        global _fp
        if _fp is not None:
            _fp.close()
            _fp = None


addons = [Record()]
