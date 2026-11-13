"""Trust the local recorder from Firefox and from the egress lookup.

Firefox does not honor Chromium's SPKI ignore list. The browser context is
told to accept the recorder's certificate, and the Python egress lookup
(which dials HTTPS through that same proxy) trusts the recorder CA plus the
public roots.
"""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import urlsplit

_TRUST_KEYS = ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE")


def browser_proxy(server: str) -> dict[str, str]:
    """The proxy dict invisible-playwright expects for the local recorder.

    No username and no password. The recorder is open on loopback. An upstream
    proxy, when there is one, is configured on mitmcloak, not here.
    """
    parts = urlsplit(server)
    if parts.username or parts.password:
        raise ValueError("the recorder address has no userinfo")
    if parts.scheme != "http" or parts.hostname != "127.0.0.1" or not parts.port:
        raise ValueError("the browser talks only to the local recorder")
    return {"server": f"http://127.0.0.1:{parts.port}"}


def write_trust_bundle(ca_pem: Path, dest: Path) -> Path:
    """Public roots plus the recorder CA, so HTTPS through the recorder verifies."""
    import certifi

    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(Path(certifi.where()).read_bytes() + b"\n" + ca_pem.read_bytes())
    return dest


def use_trust_bundle(path: Path) -> dict[str, str | None]:
    """Point this process's HTTPS clients at `path`. Returns the previous values."""
    saved = {key: os.environ.get(key) for key in _TRUST_KEYS}
    value = str(path)
    for key in _TRUST_KEYS:
        os.environ[key] = value
    return saved


def restore_trust(saved: dict[str, str | None] | None) -> None:
    if not saved:
        return
    for key, value in saved.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value


def accept_recorder_certificate() -> None:
    """Make every invisible-playwright context accept the recorder certificate.

    The library's own context options do not include this, and Firefox will
    not load a page whose certificate the recorder just signed. Patching the
    shared helper covers the window here and the agent server in this process.
    """
    from invisible_playwright._session import CommonLaunch

    current = CommonLaunch._default_context_kwargs
    if getattr(current, "_oby_trust", False):
        return

    def wrapped(self):
        kwargs = current(self)
        kwargs["ignore_https_errors"] = True
        return kwargs

    wrapped._oby_trust = True  # type: ignore[attr-defined]
    CommonLaunch._default_context_kwargs = wrapped  # type: ignore[method-assign]
    try:
        from oby.scripts import install_script_watcher

        install_script_watcher()
    except Exception as exc:
        import sys

        print(f"oby: could not install the script watcher: {exc}", file=sys.stderr)
