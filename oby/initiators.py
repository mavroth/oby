"""Which script started each request, and whether every request was recorded.

The DevTools watch in chrome.py writes every request the browser makes to
initiators.jsonl as it happens: what caused it (a script, a fetch, the
document) and, for a request made from JavaScript, the frame that made it:
file, line, column, and function. A request, its frame, and what became of
it come as separate lines, in any order, joined by `rid`.

Nothing is injected into the page for this. The reports are matched to the
recorded exchanges by method and URL, in the order both happened.
"""

from __future__ import annotations

import json
from pathlib import Path

INITIATORS_NAME = "initiators.jsonl"

def read(path: Path) -> list[dict]:
    """Requests in the order they were reported, each with its frame when one came."""
    requests: list[dict] = []
    by_rid: dict = {}
    frames: dict = {}
    updates: dict = {}
    if not path.is_file():
        return requests
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            rid = row.get("rid")
            if "update" in row and "url" not in row:
                updates.setdefault(rid, {}).update(row["update"])
                if rid in by_rid:
                    by_rid[rid].update(row["update"])
                continue
            if "frame" in row and "url" not in row:
                frames[rid] = row["frame"]
                if rid in by_rid:
                    by_rid[rid]["frame"] = row["frame"]
                continue
            if rid in frames:
                row["frame"] = frames[rid]
            if rid in updates:
                row.update(updates[rid])
            by_rid[rid] = row
            requests.append(row)
    return requests


def match(flows: list[dict], requests: list[dict]) -> list[dict | None]:
    """One initiator per exchange, or None. Same method and URL, first come first."""
    waiting: dict[tuple[str, str], list[dict]] = {}
    for request in requests:
        waiting.setdefault((request.get("method", "GET").upper(), request.get("url", "")), []).append(request)
    matched: list[dict | None] = []
    for flow in flows:
        queue = waiting.get((str(flow.get("method") or "GET").upper(), str(flow.get("url") or "")))
        matched.append(shape(queue.pop(0)) if queue else None)
    return matched


def shape(request: dict) -> dict:
    found = {"type": request.get("type") or "other"}
    if request.get("document"):
        found["document"] = request["document"]
    if isinstance(request.get("frame"), dict):
        found.update(request["frame"])
    return found


def chrome(initiator: dict) -> dict:
    """The `_initiator` Chrome writes in a HAR. Its lines and columns count from 0."""
    if "url" not in initiator:
        return {"type": "parser" if initiator.get("type") in ("document", "subdocument") else "other"}

    def zero(value) -> int:
        return max(0, value - 1) if isinstance(value, int) else 0

    return {
        "type": "script",
        "stack": {
            "callFrames": [
                {
                    "functionName": initiator.get("function") or "",
                    "url": initiator["url"],
                    "lineNumber": zero(initiator.get("line")),
                    "columnNumber": zero(initiator.get("column")),
                }
            ]
        },
    }


def missing(flows: list[dict], requests: list[dict]) -> list[dict]:
    """Requests the browser says it made that have no recorded exchange.

    This is the check that the recorder saw everything. The browser's list and
    the recorder's are made independently, one inside the browser and one on
    the wire. A request answered from the browser's cache never reaches the
    wire, and neither does a data:, blob:, or about: URL, so those are left
    out or expected here.
    """
    recorded: dict[tuple[str, str], int] = {}
    for flow in flows:
        key = (str(flow.get("method") or "GET").upper(), str(flow.get("url") or ""))
        recorded[key] = recorded.get(key, 0) + 1
    absent: list[dict] = []
    for request in requests:
        url = str(request.get("url") or "")
        if not url.lower().startswith(("http://", "https://", "ws://", "wss://")):
            continue
        key = (str(request.get("method") or "GET").upper(), url)
        if recorded.get(key, 0) > 0:
            recorded[key] -= 1
            continue
        item = {"method": key[0], "url": url, "type": request.get("type") or ""}
        for name in ("status", "cached", "service_worker", "blocked"):
            if request.get(name):
                item[name] = request[name]
        absent.append(item)
    return absent


def coverage(out: Path, flows: list[dict]) -> dict:
    """The browser's request list against the recording.

    `missing` is the list that matters: the browser got an answer from the
    network and the recorder has no exchange for it. It should be empty.
    `from_cache` requests were answered by the browser's own cache or a
    service worker, so nothing was sent. `unanswered` requests never got an
    answer in the browser either: it dropped them before sending, which is
    what a page does to its pending requests when it navigates away.
    """
    requests = read(Path(out) / INITIATORS_NAME)
    absent = missing(flows, requests)
    cached = [item for item in absent if item.get("cached") or item.get("service_worker")]
    lost = [item for item in absent if item.get("status") and item not in cached]
    unanswered = [item for item in absent if item not in cached and item not in lost]
    return {
        "browser_reported": len(requests),
        "recorded": len(flows),
        "missing": lost,
        "from_cache": len(cached),
        "unanswered": unanswered,
    }


def for_folder(out: Path, flows: list[dict]) -> list[dict | None]:
    return match(flows, read(Path(out) / INITIATORS_NAME))
