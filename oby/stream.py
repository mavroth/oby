"""Carry each request through mitmcloak's session and pass the body on as it arrives.

mitmcloak asks httpcloak for a response and hands it over when the body is
complete, with a deadline for the whole thing. A page that reads a response
as it arrives (an event stream, a chat reply, a long download) then waits
for the end, and a response with no end, or one slower than the deadline,
is an error. httpcloak's buffered call also fails to decode a 304 that
carries a Content-Encoding header and no body, so a cache revalidation
came back as a 502.

So a request is opened here as a stream, on the same upstream session
mitmcloak would have used, with the same headers. The flow is pointed at a
relay on loopback, which passes each chunk on as it arrives and notes when
it came. The browser's TLS mirror is unchanged: the origin is still dialed
by httpcloak. mitmcloak still carries what this module leaves alone: a
request whose body is not text, since the streaming call takes the body as
a string, and a HEAD.

The relay is the recorder's own listener. It answers only a token this
module issued for one request.
"""

from __future__ import annotations

import asyncio
import secrets
import threading
import time

RELAY_HOST = "127.0.0.1"
RELAY_PATH = "/__oby_stream__/"
_FIELDS = (b"data", b"event", b"id", b"retry")
_NO_BODY = frozenset({204, 304})

# token -> entry. An entry is removed when its row has been written.
OPEN: dict[str, dict] = {}


def wants_stream(request) -> bool:
    """True for a request an EventSource, or a fetch that reads events, sends."""
    headers = request.headers
    if headers.get("Sec-WebSocket-Version"):
        return False
    if "text/event-stream" not in (headers.get("accept") or "").lower():
        return False
    if request.method.upper() not in ("GET", "POST"):
        return False
    body = request.raw_content or b""
    if body:
        # The streaming call takes the body as text.
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            return False
    return True


# A HEAD answer has no body, and the relay leg is a GET, so it stays with mitmcloak.
_RELAY_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})


def wants_relay(request) -> bool:
    """True for a request this module can open as a stream."""
    if request.headers.get("Sec-WebSocket-Version"):
        return False
    if request.method.upper() not in _RELAY_METHODS:
        return False
    body = request.raw_content or b""
    if body:
        try:
            body.decode("utf-8")
        except UnicodeDecodeError:
            return False
    return True


def events_with_times(chunks: list[tuple[float, bytes]]) -> list[float]:
    """The arrival time of each complete event, in order.

    An event ends at a blank line. Its time is when the chunk holding that
    blank line arrived.
    """
    times: list[float] = []
    tail = b""
    for when, data in chunks:
        text = (tail + data).replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        pieces = text.split(b"\n\n")
        tail = pieces.pop()
        times.extend(when for piece in pieces if _is_event(piece))
    return times


def _is_event(block: bytes) -> bool:
    """A block with a field an EventSource reads. A comment alone is a keep-alive."""
    return any(line.split(b":", 1)[0] in _FIELDS for line in block.split(b"\n"))


def leave_to_relay(bridge) -> None:
    """Have mitmcloak pass over a flow that this module already opened upstream."""
    resolver = bridge.resolver
    if getattr(resolver, "_oby_relay", False):
        return
    original = resolver.should_bypass

    def should_bypass(flow) -> bool:
        if (getattr(flow, "metadata", None) or {}).get("oby_stream"):
            return True
        return original(flow)

    resolver.should_bypass = should_bypass
    resolver._oby_relay = True


class Relay:
    def __init__(self) -> None:
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> int:
        if self._server is None:
            self._server = await asyncio.start_server(self._serve, RELAY_HOST, 0)
            self.port = self._server.sockets[0].getsockname()[1]
        return self.port

    def close(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None

    async def _serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        entry = None
        try:
            line = await reader.readline()
            parts = line.split()
            token = parts[1].decode("latin-1").rsplit("/", 1)[-1] if len(parts) > 1 else ""
            while (await reader.readline()) not in (b"\r\n", b"\n", b""):
                pass
            entry = OPEN.get(token)
            if entry is None or entry.get("served"):
                # Not a token issued here. Say nothing.
                return
            entry["served"] = True
            await self._pump(entry, reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            if entry is not None:
                finish(entry)
            try:
                writer.close()
            except Exception:
                pass

    async def _pump(self, entry: dict, reader, writer) -> None:
        status = int(entry["status"])
        if status in _NO_BODY:
            writer.write(f"HTTP/1.1 {status} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
            await writer.drain()
            entry["complete"] = True
            return
        writer.write(f"HTTP/1.1 {status} OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue = asyncio.Queue()

        def read() -> None:
            # One thread per stream. An idle stream blocks in the read, and
            # the shared pool would run out of threads.
            try:
                for chunk in entry["upstream"].iter_content(65536):
                    loop.call_soon_threadsafe(queue.put_nowait, chunk)
            except Exception as exc:
                entry["error"] = str(exc)
            finally:
                try:
                    loop.call_soon_threadsafe(queue.put_nowait, None)
                except RuntimeError:
                    pass

        threading.Thread(target=read, name="oby-stream", daemon=True).start()
        # The recorder closing this connection is the browser leaving.
        gone = asyncio.ensure_future(reader.read())
        try:
            while True:
                waiting = asyncio.ensure_future(queue.get())
                done, _ = await asyncio.wait({waiting, gone}, return_when=asyncio.FIRST_COMPLETED)
                if waiting not in done:
                    waiting.cancel()
                    # The browser stops reading a redirect, and closes on the
                    # last byte of a body it knows the length of. If the end
                    # is already here, the body was whole.
                    while not queue.empty():
                        chunk = queue.get_nowait()
                        if chunk is None:
                            entry["complete"] = "error" not in entry
                            break
                        entry["chunks"].append((time.time(), chunk))
                    return
                chunk = waiting.result()
                if chunk is None:
                    entry["complete"] = "error" not in entry
                    writer.write(b"0\r\n\r\n")
                    await writer.drain()
                    return
                entry["chunks"].append((time.time(), chunk))
                writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                await writer.drain()
        finally:
            gone.cancel()


def finish(entry: dict) -> None:
    """Close the upstream stream once. The entry stays until its row is written."""
    if entry.get("ended") is not None:
        return
    entry["ended"] = time.time()
    try:
        entry["upstream"].close()
    except Exception:
        pass


def new_entry(
    *, upstream, flow, request_row: dict, headers: list[list[str]], cloak: dict, events: bool = True
) -> str:
    token = secrets.token_urlsafe(18)
    OPEN[token] = {
        "token": token,
        "events": events,
        "upstream": upstream,
        "flow": flow,
        "request_row": request_row,
        "status": upstream.status_code,
        "response_headers": headers,
        "protocol": getattr(upstream, "protocol", None),
        "opened": time.time(),
        "chunks": [],
        "ended": None,
        "complete": False,
        "mitmcloak": cloak,
    }
    return token


def body_is_whole(entry: dict) -> bool:
    """True when what arrived is all there was, though the end was not seen.

    A redirect's body is not read by the browser at all. Otherwise the
    Content-Length says, when the body was not compressed on the way.
    """
    if 300 <= int(entry["status"]) < 400:
        return True
    headers = {name.lower(): value for name, value in entry["response_headers"]}
    if headers.get("content-encoding", "identity").strip().lower() not in ("", "identity"):
        return False
    try:
        return int(headers["content-length"]) == sum(len(data) for _when, data in entry["chunks"])
    except (KeyError, ValueError):
        return False


def stream_row(entry: dict, body_field) -> dict:
    """The exchange as it would have been recorded, with the body that arrived."""
    row = dict(entry["request_row"])
    chunks = entry["chunks"]
    row["status"] = entry["status"]
    row["response_http_version"] = {"h2": "HTTP/2.0", "h3": "HTTP/3.0"}.get(entry["protocol"] or "", "HTTP/1.1")
    row["response_headers"] = entry["response_headers"]
    row["response_header_block"] = "".join(f"{name}: {value}\r\n" for name, value in entry["response_headers"])
    row["response_body"] = body_field(b"".join(data for _when, data in chunks))
    ended = entry["ended"] if entry["ended"] is not None else time.time()
    row["ended"] = ended
    timing = dict(row.get("timing") or {})
    timing["response_start"] = entry["opened"]
    timing["response_end"] = ended
    row["timing"] = timing
    if entry.get("events", True):
        row["stream"] = {
            "complete": bool(entry["complete"]),
            "chunks": [[when, len(data)] for when, data in chunks],
            "event_times": events_with_times(chunks),
        }
        if entry.get("error"):
            row["stream"]["error"] = entry["error"]
    elif not entry["complete"] and not body_is_whole(entry):
        # The browser left, or the session ended, before the body finished.
        row["response_body"]["truncated"] = True
        row["error"] = entry.get("error") or "the body was still arriving when the request ended"
    row["mitmcloak"] = entry["mitmcloak"]
    return row
