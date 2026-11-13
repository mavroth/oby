import sys
from pathlib import Path

from oby.proxy import Mitm, build_mitmdump_command, mitmdump_argv, redact_proxy
from oby.record import body_field, exchange, header_pairs


class _Headers:
    def __init__(self, fields):
        self.fields = fields

    def items(self):
        return [(n.decode(), v.decode()) for n, v in self.fields]


class _Message:
    def __init__(self, raw, headers, status=None, version="HTTP/2"):
        self.raw_content = raw
        self.content = raw
        self.headers = headers
        self.http_version = version
        self.status_code = status


class _Request(_Message):
    def __init__(self):
        super().__init__(b'{"a":1}', _Headers([(b"Cookie", b"a=1"), (b"X-Odd", b"1"), (b"Cookie", b"b=2")]))
        self.pretty_url = "https://example.com/api"
        self.method = "POST"
        self.http_version = "HTTP/2"


class _Flow:
    def __init__(self):
        self.request = _Request()
        self.response = _Message(b"ok", _Headers([(b"Content-Type", b"text/plain")]), status=200)
        self.error = None
        self.metadata = {"mitmcloak": {"preset": "mirrored", "via": "mirror"}}


def test_header_order_and_duplicates_survive():
    pairs = header_pairs(
        _Headers(
            [
                (b"Proxy-Authorization", b"Basic eHh4"),
                (b"Cookie", b"a=1"),
                (b"X-Odd", b"1"),
                (b"Cookie", b"b=2"),
            ]
        )
    )
    assert pairs == [["Cookie", "a=1"], ["X-Odd", "1"], ["Cookie", "b=2"]]


def test_exchange_keeps_body_and_preset():
    record = exchange(_Flow())
    assert record["method"] == "POST"
    assert record["status"] == 200
    assert record["request_body"]["text"] == '{"a":1}'
    assert record["request_headers"][0] == ["Cookie", "a=1"]
    assert record["request_headers"][2] == ["Cookie", "b=2"]
    assert "Cookie: a=1\r\nX-Odd: 1\r\nCookie: b=2" in record["request_header_block"]
    assert record["mitmcloak"]["via"] == "mirror"


def test_body_marks_truncation(monkeypatch):
    monkeypatch.setenv("OBY_MAX_BODY", "4")
    field = body_field(b"abcdef")
    assert field["truncated"] is True
    assert field["bytes"] == 6
    assert field["text"] == "abcd"


def test_redact_proxy_drops_userinfo():
    assert redact_proxy("http://user:secret@proxy.example:8080") == "http://proxy.example:8080"
    assert redact_proxy(None) is None


def test_mitmdump_comes_from_this_environment():
    argv = mitmdump_argv()
    assert Path(argv[0]).resolve().is_relative_to(Path(sys.prefix).resolve())


def test_browser_proxy_is_the_open_recorder():
    from oby.trust import browser_proxy

    assert browser_proxy("http://127.0.0.1:9") == {"server": "http://127.0.0.1:9"}
    try:
        browser_proxy("http://oby:secret@127.0.0.1:9")
    except ValueError as exc:
        assert "userinfo" in str(exc)
    else:
        raise AssertionError("userinfo was accepted")


def test_trust_bundle_keeps_public_roots_and_the_recorder_ca(tmp_path: Path):
    from oby.trust import write_trust_bundle

    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nOBYRECORDER\n-----END CERTIFICATE-----\n", encoding="utf-8")
    bundle = write_trust_bundle(ca, tmp_path / "trust.pem")
    text = bundle.read_text(encoding="utf-8")
    assert "OBYRECORDER" in text
    assert text.count("BEGIN CERTIFICATE") > 1


def test_recorder_certificate_is_accepted_on_the_context():
    from invisible_playwright._session import CommonLaunch

    from oby.trust import accept_recorder_certificate

    original = CommonLaunch._default_context_kwargs

    def fake(self):
        return {"locale": "en-US"}

    CommonLaunch._default_context_kwargs = fake
    try:
        accept_recorder_certificate()
        kwargs = CommonLaunch._default_context_kwargs(None)
        assert kwargs["ignore_https_errors"] is True
        assert kwargs["locale"] == "en-US"
    finally:
        CommonLaunch._default_context_kwargs = original


def test_recorder_proxy_has_no_userinfo(tmp_path: Path):
    mitm = Mitm(tmp_path)
    mitm.port = 9
    assert mitm.server == "http://127.0.0.1:9"
    command = build_mitmdump_command(
        listen_port=9,
        confdir=tmp_path / "mitm",
        flow_path=tmp_path / "flows.mitm",
        export_dir=tmp_path / "presets",
        catalogue_dir=tmp_path / "seen",
        upstream="http://user:secret@proxy.example:8080",
    )
    assert "mitmcloak_headers=exact" in command
    assert "--proxyauth" not in command
    assert "mitmcloak_proxy=http://user:secret@proxy.example:8080" in command


def _h2_frame(ftype: int, body: bytes, stream_id: int = 0, flags: int = 0) -> bytes:
    return (
        len(body).to_bytes(3, "big")
        + bytes((ftype, flags))
        + stream_id.to_bytes(4, "big")
        + body
    )


class _LayerData:
    def __init__(self, buf: bytes, conn_id: str = "c1"):
        self.buf = buf
        self.layer = object()
        self.context = type("Context", (), {})()
        self.context.client = type("Client", (), {"id": conn_id})()

    def data_client(self) -> bytes:
        return self.buf


def test_pseudo_header_order_waits_until_the_headers_frame_arrives():
    import hpack

    from oby.record import _CaptureH2, _h2, _waiting

    _h2.clear()
    _waiting.clear()
    magic = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    settings = _h2_frame(0x04, b"\x00\x01\x00\x00\x00\x01")
    block = hpack.Encoder().encode(
        [
            (":method", "GET"),
            (":path", "/"),
            (":authority", "example.com"),
            (":scheme", "https"),
        ]
    )
    headers = _h2_frame(0x01, block, stream_id=1, flags=0x04)
    addon = _CaptureH2()

    early = _LayerData(magic + settings)
    addon.next_layer(early)
    assert early.layer is None
    assert "c1" not in _h2

    ready = _LayerData(magic + settings + headers)
    addon.next_layer(ready)
    assert ready.layer is not None
    assert _h2["c1"]["pseudo_order"] == [":method", ":path", ":authority", ":scheme"]
    assert _h2["c1"]["settings"] == [[1, 1]]
