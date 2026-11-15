"""Open each request upstream as a stream, before mitmcloak sees it.

Loaded ahead of the cloak addon on purpose. mitmcloak leaves a request alone
when a response is already set or when this addon marked it. The HTTP/2
capture stays in record.py, which is loaded later so it can place itself last.
"""

from __future__ import annotations

import asyncio
import time



# How long a server may take to start answering, in seconds. Chrome itself
# gives up after five minutes. mitmcloak's own limit is thirty
# seconds for the whole response.
OPEN_TIMEOUT = 300


class Stream:
    """Open the request upstream as a stream and hand the flow to the relay.

    Runs before mitmcloak, and uses mitmcloak's own session, preset, and
    header handling, so the origin sees the same client either way. A GET
    that fails to open is left untouched and mitmcloak carries it as usual.
    """

    def __init__(self) -> None:
        from oby.stream import Relay

        self.relay = Relay()

    async def request(self, flow) -> None:
        from oby import stream

        if flow.response is not None or not getattr(flow, "live", True):
            return
        if not stream.wants_relay(flow.request):
            return
        try:
            from mitmproxy import ctx
            from mitmcloak import headers as hdrs

            from oby.record import exchange

            bridge = ctx.master.addons.get("bridge")
            if bridge is None or bridge.resolver.should_bypass(flow) or bridge._targets_self(flow):
                return
            if len(flow.request.raw_content or b"") > ctx.options.mitmcloak_max_body:
                return
            decision = bridge.resolver.decide(
                flow, bridge._mode(), lambda: bridge._mirror_preset(flow), bridge._preset()
            )
            if not decision.preset and decision.session is None:
                return
            session = bridge._session_for(flow, decision)
            stream.leave_to_relay(bridge)
            started = time.perf_counter()
            body = flow.request.raw_content or b""
            upstream = await session.request_stream_async(
                flow.request.method,
                flow.request.url,
                data=body or None,
                timeout=OPEN_TIMEOUT,
                **bridge._header_kwargs(flow, decision),
            )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            # The request may have reached the origin. Letting mitmcloak send
            # it again is safe for a GET and not for a POST.
            text = str(exc)
            late = "deadline" in text or "timeout" in text.lower()
            if (late or flow.request.method.upper() != "GET") and "bridge" in locals() and "session" in locals():
                # A request that already waited out the deadline is not sent again.
                try:
                    bridge._fail(flow, 504 if late else 502, text)
                except Exception:
                    pass
            return
        try:
            port = await self.relay.start()
            pairs = [
                [name.decode("latin-1"), value.decode("latin-1")]
                for name, value in hdrs.response_pairs(upstream.headers)
            ]
            token = stream.new_entry(
                upstream=upstream,
                flow=flow,
                request_row=exchange(flow),
                headers=pairs,
                events=stream.wants_stream(flow.request),
                cloak={
                    "preset": decision.preset,
                    "via": decision.reason,
                    "upstream": getattr(upstream, "protocol", None),
                    "ms": round((time.perf_counter() - started) * 1000, 1),
                    "streamed": True,
                },
            )
        except Exception:
            try:
                upstream.close()
            except Exception:
                pass
            return
        try:
            bridge._requested.add(flow.client_conn.id)
        except Exception:
            pass
        flow.metadata["oby_stream"] = token
        # The relay leg. The recorded request is the copy taken above.
        flow.request.scheme = "http"
        flow.request.host = stream.RELAY_HOST
        flow.request.port = port
        flow.request.path = stream.RELAY_PATH + token
        flow.request.method = "GET"
        flow.request.content = b""

    def responseheaders(self, flow) -> None:
        from oby import stream

        entry = stream.OPEN.get(flow.metadata.get("oby_stream") or "")
        if entry is None or flow.response is None:
            return
        from mitmproxy import http

        fields = [(n.encode("latin-1"), v.encode("latin-1")) for n, v in entry["response_headers"]]
        if entry["request_row"].get("request_http_version", "").startswith("HTTP/1"):
            fields.append((b"Transfer-Encoding", b"chunked"))
        flow.response.headers = http.Headers(fields)
        flow.response.stream = True

    def done(self) -> None:
        self.relay.close()


addons = [Stream()]
