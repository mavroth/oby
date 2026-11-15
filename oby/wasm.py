"""Read the names out of a WebAssembly module.

A module is opaque bytes, but its import and export sections are plain
names: what it asks the page for, and what it hands back. Those are what a
reader searches for first, so they are listed next to the module.
"""

from __future__ import annotations

_KINDS = ("function", "table", "memory", "global", "tag")
_MAGIC = b"\x00asm"


class _Reader:
    def __init__(self, data: bytes, at: int = 0, end: int | None = None):
        self.data = data
        self.at = at
        self.end = len(data) if end is None else end

    def byte(self) -> int:
        if self.at >= self.end:
            raise ValueError("ran off the end of the module")
        value = self.data[self.at]
        self.at += 1
        return value

    def u32(self) -> int:
        result = shift = 0
        while True:
            value = self.byte()
            result |= (value & 0x7F) << shift
            if not value & 0x80:
                return result
            shift += 7
            if shift > 35:
                raise ValueError("a number in the module is too long")

    def name(self) -> str:
        size = self.u32()
        if self.at + size > self.end:
            raise ValueError("a name runs off the end of the module")
        text = self.data[self.at : self.at + size].decode("utf-8", errors="replace")
        self.at += size
        return text

    def limits(self) -> None:
        flags = self.byte()
        self.u32()
        if flags & 1:
            self.u32()


def _import(reader: _Reader) -> dict:
    module, field, kind = reader.name(), reader.name(), reader.byte()
    if kind == 0:
        reader.u32()
    elif kind == 1:
        reader.byte()
        reader.limits()
    elif kind == 2:
        reader.limits()
    elif kind == 3:
        reader.byte()
        reader.byte()
    elif kind == 4:
        reader.byte()
        reader.u32()
    else:
        raise ValueError("an import of an unknown kind")
    return {"module": module, "name": field, "kind": _KINDS[kind]}


def describe(data: bytes) -> dict:
    """`imports`, `exports`, and how many functions the module defines. Empty for bytes that are not a module."""
    if data[:4] != _MAGIC or len(data) < 8:
        return {}
    found: dict = {"imports": [], "exports": [], "functions": 0}
    reader = _Reader(data, 8)
    try:
        while reader.at < reader.end:
            section, size = reader.byte(), reader.u32()
            body = _Reader(data, reader.at, min(reader.at + size, len(data)))
            reader.at += size
            if section == 2:
                found["imports"] = [_import(body) for _ in range(body.u32())]
            elif section == 3:
                found["functions"] = body.u32()
            elif section == 7:
                for _ in range(body.u32()):
                    name, kind = body.name(), body.byte()
                    body.u32()
                    found["exports"].append({"name": name, "kind": _KINDS[kind] if kind < len(_KINDS) else "other"})
    except (ValueError, IndexError):
        # What was read before the damage is still true.
        found["incomplete"] = True
    return found
