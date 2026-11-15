"""Cookies and localStorage for a browser an agent drives.

`oby browse` saves storage.json when the window closes. Under `oby mcp` the
server remembers its browser context here, so the same file can be written
when the agent asks for a save and again just before the browser is closed.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

STORAGE_NAME = "storage.json"
_live: list = []


def remember(target) -> None:
    """Keep the launcher's result. It is a context, or a browser that has contexts."""
    if target is not None and all(target is not seen for seen in _live):
        _live.append(target)


def forget(target) -> None:
    _live[:] = [seen for seen in _live if seen is not target]


def _contexts() -> list:
    found = []
    for target in _live:
        if callable(getattr(target, "storage_state", None)):
            found.append(target)
            continue
        try:
            found.extend(getattr(target, "contexts", None) or [])
        except Exception:
            continue
    return found


def merge(states: list[dict]) -> dict:
    merged: dict = {"cookies": [], "origins": []}
    for state in states:
        if not isinstance(state, dict):
            continue
        merged["cookies"].extend(state.get("cookies") or [])
        merged["origins"].extend(state.get("origins") or [])
    return merged


async def save_async(out: Path | None = None, timeout: float = 10) -> dict | None:
    """Write storage.json from every open context. Returns the counts, or None."""
    folder = Path(out) if out is not None else Path(os.environ.get("OBY_OUT") or "")
    if not str(folder) or str(folder) == ".":
        return None
    states = []
    for context in _contexts():
        try:
            states.append(await asyncio.wait_for(context.storage_state(), timeout))
        except Exception:
            continue
    if not states:
        return None
    state = merge(states)
    folder.mkdir(parents=True, exist_ok=True)
    partial = folder / (STORAGE_NAME + ".part")
    partial.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    partial.replace(folder / STORAGE_NAME)
    return {"cookies": len(state["cookies"]), "origins": len(state["origins"])}
