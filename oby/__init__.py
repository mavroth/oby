"""Record a stealth browser session as a HAR, including the JavaScript that ran."""

__all__ = ["Session"]


def __getattr__(name: str):
    # Session pulls in the pointer library, which `oby mcp` never needs.
    if name == "Session":
        from oby.session import Session

        return Session
    raise AttributeError(name)
