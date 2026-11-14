"""Let this Firefox attach a worker thread.

The stealth engine reads ``zoom.stealth.debugger.force_detach`` from
``Services.prefs`` at the start of ``ThreadActor.attach``. A worker thread has
``Services`` and no prefs service, so attach throws and the worker's scripts
are never reported. A dedicated worker is also ignored when its window id is
still empty at startup. A network worker stays frozen until its script has
already been fetched, so that script never loads. The replacements are the
same number of bytes: the members are stored uncompressed in ``browser/omni.ja``,
and nothing after them has to move.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

OLD = (
    b'    let forceDetach = Services.prefs.getBoolPref("zoom.stealth.debugger.force_detach", false);\n'
    b"    if (this.alreadyAttached || forceDetach) {"
)
NEW = (
    b'    let fd=!Services.prefs?false:Services.prefs.getBoolPref("zoom.stealth.debugger.force_detach",false);\n'
    b"    if(this.alreadyAttached||fd)   {"
)
# A dedicated worker is dropped when its window id is not filled in yet.
# That id is often empty at the moment the worker starts, so the script is
# never reported. Accepting it here still requires the worker to be in the
# debugged document's process. Same length, stored uncompressed.
FILTER_OLD = b"return false;\n    }\n\n    if (dbg.type === TYPE_SERVICE)"
FILTER_NEW = b"return true ;\n    }\n\n    if (dbg.type === TYPE_SERVICE)"
# In the content process the browsing context lookup is empty, so the worker
# is dropped before its scripts can be read. A worker there still belongs to
# the page being recorded.
CONTEXT_OLD = b"if (!browsingContext) {\n        return false;\n      }\n      for (const subBrowsi"
CONTEXT_NEW = b"if (!browsingContext) {\n        return true ;\n      }\n      for (const subBrowsi"
# A network worker is frozen until session data says it is ready. That wait
# never finishes for a script that still has to be fetched, so the thread
# never answers. Release it when the thread exists. Same length, stored
# uncompressed. The spaces keep the following bytes in place.
RELEASE_OLD = (
    b'            if (message.type == "session-data-processed") {\n'
    b"              // The thread actor has finished processing session data, including breakpoints.\n"
    b"              // Allow content to begin executing in the worker and possibly hit early breakpoints.\n"
    b"              dbg.setDebuggerReady(true);\n"
    b"            }\n"
)
RELEASE_NEW = (
    b'            if (message.type == "connected" || message.type == "session-data-processed") {\n'
    b"              dbg.setDebuggerReady(true);\n"
    b"              // The script must be fetched, so release as soon as the thread exists."
    + b" " * 78
    + b"\n            }\n"
)
# Pausing a worker here keeps a network script from being fetched at all.
# Let it run. Its thread still reports the script once the watcher connects.
# `true ` is the same width as `false`.
READY_OLD = b"    try {\n      dbg.setDebuggerReady(false);\n    } catch (e) {"
READY_NEW = b"    try {\n      dbg.setDebuggerReady(true );\n    } catch (e) {"
_REPLACEMENTS = (
    (OLD, NEW),
    (FILTER_OLD, FILTER_NEW),
    (CONTEXT_OLD, CONTEXT_NEW),
    (RELEASE_OLD, RELEASE_NEW),
    (READY_OLD, READY_NEW),
)


def patch_browser_jar(path: Path) -> str:
    """Return ``patched``, ``ready``, or ``unchanged``."""
    if any(len(old) != len(new) for old, new in _REPLACEMENTS):
        return "unchanged"
    data = path.read_bytes()
    changed = False
    for old, new in _REPLACEMENTS:
        found = data.count(old)
        if found == 0:
            if new not in data:
                return "unchanged"
            continue
        if found != 1:
            return "unchanged"
        data = data.replace(old, new, 1)
        changed = True
    if not changed:
        return "ready"
    path.write_bytes(data)
    return "patched"


def patch_engine(root: Path | None = None) -> str:
    """Patch the engine Firefox will launch. Missing or read-only files stay as they are."""
    if root is None:
        raw = os.environ.get("INVISIBLE_PLAYWRIGHT_ENGINE_DIR", "")
        root = Path(raw) if raw else None
    if root is None or not root.is_dir():
        return "unchanged"
    jars = [path for path in root.rglob("omni.ja") if path.parent.name == "browser"]
    if not jars:
        return "unchanged"
    try:
        return patch_browser_jar(jars[0])
    except OSError as exc:
        print(f"oby: could not prepare worker scripts: {exc}", file=sys.stderr)
        return "unchanged"


def main() -> None:
    print(patch_engine(), file=sys.stderr)


if __name__ == "__main__":
    main()
