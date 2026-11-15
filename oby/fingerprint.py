"""Which fingerprinting APIs a page called, and from which script.

Off unless asked for. The recording itself injects nothing into a page.
This does: a script that runs before the page's own wraps the APIs a
fingerprinting script reads (canvas, WebGL, audio, navigator, screen, fonts,
WebRTC, storage, timing, and the checks a script makes on its own
environment) and notes each call. A wrapper answers `toString()` like the
native function, leaves no global behind, and sends nothing, but a script
that looks hard enough can still tell it is there, so a site may behave
differently with this on.

Each call is reported with its arguments, a short form of what it returned,
and the script frame that made it. A long result, such as a canvas image, is
kept as its length and a hash, so two visits can be compared. After the
first calls of one API in a page only the count grows. APIs a page calls
thousands of times (layout reads, timers) are counted and not detailed.

The reports go to fingerprint.jsonl as they arrive. fingerprint.json is the
summary, by API and by script.
"""

from __future__ import annotations

import json
from pathlib import Path

LOG_NAME = "fingerprint.jsonl"
SUMMARY_NAME = "fingerprint.json"
DETAIL = 20

NOTE = (
    "Fingerprinting APIs the page called. Wrappers were installed in the page before its own scripts ran, "
    "so a site can detect this log. `count` is every call. `calls` are the first of each API in each page, "
    "with arguments, a short form of the result, and the script frame that called. "
    "A long result is its length and an FNV-1a hash."
)

# category, where the member lives, how it is wrapped, the members.
# m: method. g: getter. c: constructor. A trailing ~ is counted only.
_TARGETS = [
    ("canvas", "HTMLCanvasElement.prototype", "m", "toDataURL toBlob getContext captureStream"),
    ("canvas", "OffscreenCanvas.prototype", "m", "convertToBlob getContext transferToImageBitmap"),
    ("canvas", "CanvasRenderingContext2D.prototype", "m", "getImageData measureText fillText strokeText isPointInPath isPointInStroke"),
    ("canvas", "OffscreenCanvasRenderingContext2D.prototype", "m", "getImageData measureText fillText"),
    ("webgl", "WebGLRenderingContext.prototype", "m", "getParameter getExtension getSupportedExtensions getShaderPrecisionFormat getContextAttributes readPixels"),
    ("webgl", "WebGL2RenderingContext.prototype", "m", "getParameter getExtension getSupportedExtensions getShaderPrecisionFormat getContextAttributes readPixels"),
    ("webgl", "GPU.prototype", "m", "requestAdapter getPreferredCanvasFormat"),
    ("webgl", "GPUAdapter.prototype", "m", "requestAdapterInfo requestDevice"),
    ("audio", "window", "c", "AudioContext OfflineAudioContext webkitAudioContext webkitOfflineAudioContext"),
    ("audio", "BaseAudioContext.prototype", "m", "createOscillator createDynamicsCompressor createAnalyser createBiquadFilter createGain"),
    ("audio", "OfflineAudioContext.prototype", "m", "startRendering"),
    ("audio", "AudioBuffer.prototype", "m", "getChannelData copyFromChannel"),
    ("audio", "AnalyserNode.prototype", "m", "getFloatFrequencyData getByteFrequencyData getFloatTimeDomainData"),
    ("navigator", "Navigator.prototype", "g",
     "userAgent appVersion platform vendor product productSub hardwareConcurrency deviceMemory language languages "
     "plugins mimeTypes webdriver maxTouchPoints doNotTrack cookieEnabled pdfViewerEnabled userAgentData connection "
     "onLine oscpu buildID globalPrivacyControl"),
    ("navigator", "Navigator.prototype", "m", "getBattery getGamepads javaEnabled getInstalledRelatedApps requestMediaKeySystemAccess sendBeacon"),
    ("navigator", "NavigatorUAData.prototype", "m", "getHighEntropyValues toJSON"),
    ("navigator", "NavigatorUAData.prototype", "g", "brands mobile platform"),
    ("navigator", "NetworkInformation.prototype", "g", "effectiveType downlink rtt saveData type"),
    ("navigator", "Keyboard.prototype", "m", "getLayoutMap"),
    ("navigator", "window", "m", "queryLocalFonts"),
    ("screen", "Screen.prototype", "g", "width height availWidth availHeight availLeft availTop colorDepth pixelDepth isExtended orientation"),
    ("screen", "window", "g", "devicePixelRatio innerWidth innerHeight outerWidth outerHeight screenX screenY screenLeft screenTop"),
    ("screen", "window", "m", "matchMedia"),
    ("screen", "VisualViewport.prototype", "g", "width height scale"),
    ("fonts", "FontFaceSet.prototype", "m", "check load"),
    ("fonts", "HTMLElement.prototype", "g", "offsetWidth~ offsetHeight~"),
    ("fonts", "Element.prototype", "m", "getBoundingClientRect~ getClientRects~"),
    ("fonts", "Range.prototype", "m", "getBoundingClientRect~ getClientRects~"),
    ("locale", "Intl.DateTimeFormat.prototype", "m", "resolvedOptions"),
    ("locale", "Intl.NumberFormat.prototype", "m", "resolvedOptions"),
    ("locale", "Date.prototype", "m", "getTimezoneOffset~ toLocaleString~"),
    ("media", "HTMLMediaElement.prototype", "m", "canPlayType"),
    ("media", "MediaSource", "m", "isTypeSupported"),
    ("media", "MediaDevices.prototype", "m", "enumerateDevices getUserMedia getDisplayMedia"),
    ("media", "MediaCapabilities.prototype", "m", "decodingInfo encodingInfo"),
    ("media", "SpeechSynthesis.prototype", "m", "getVoices"),
    ("permissions", "Permissions.prototype", "m", "query"),
    ("permissions", "Notification", "g", "permission"),
    ("webrtc", "window", "c", "RTCPeerConnection webkitRTCPeerConnection"),
    ("webrtc", "RTCPeerConnection.prototype", "m", "createDataChannel createOffer setLocalDescription addIceCandidate"),
    ("storage", "Storage.prototype", "m", "getItem~ setItem~ removeItem~"),
    ("storage", "Document.prototype", "g", "cookie~"),
    ("storage", "IDBFactory.prototype", "m", "open databases"),
    ("storage", "StorageManager.prototype", "m", "estimate persisted"),
    ("storage", "CacheStorage.prototype", "m", "open keys"),
    ("runtime", "Function.prototype", "m", "toString~"),
    ("runtime", "Performance.prototype", "m", "now~ getEntries getEntriesByType"),
    ("runtime", "Performance.prototype", "g", "memory timing"),
    ("runtime", "Document.prototype", "g", "visibilityState hidden referrer"),
    ("runtime", "Document.prototype", "m", "hasFocus"),
    ("runtime", "window", "c", "Worker SharedWorker"),
    ("runtime", "WebAssembly", "m", "instantiate instantiateStreaming compile compileStreaming"),
    ("runtime", "Object", "m", "getOwnPropertyDescriptor~ getOwnPropertyNames~"),
    ("runtime", "Error", "m", "captureStackTrace~"),
    ("sensors", "window", "c", "DeviceMotionEvent DeviceOrientationEvent"),
    ("sensors", "BatteryManager.prototype", "g", "charging level chargingTime dischargingTime"),
    ("sensors", "Bluetooth.prototype", "m", "getAvailability getDevices"),
    ("sensors", "USB.prototype", "m", "getDevices"),
    ("sensors", "HID.prototype", "m", "getDevices"),
]


def targets() -> list[dict]:
    """The wrapped members, one entry per place they live."""
    found = []
    for category, path, how, names in _TARGETS:
        members = [{"name": name.rstrip("~"), "quiet": name.endswith("~")} for name in names.split()]
        found.append({"category": category, "path": path, "how": how, "members": members})
    return found


def category_of(api: str) -> str:
    return _CATEGORY.get(api, "other")


def _label(path: str, name: str) -> str:
    owner = path.removesuffix(".prototype")
    return name if owner == "window" else f"{owner}.{name}"


_CATEGORY = {
    _label(entry["path"], member["name"]): entry["category"] for entry in targets() for member in entry["members"]
}

# Any wrapped member will do. The watch reads the log through this one.
ANCHOR = "HTMLCanvasElement.prototype.toDataURL"
MAX_ROWS = 5000

_HOOK = r"""
(() => {
  const apply = Reflect.apply, construct = Reflect.construct, define = Object.defineProperty;
  const describe = Object.getOwnPropertyDescriptor, stringify = JSON.stringify, ErrorCtor = Error;
  const clock = Date.now, isArray = Array.isArray;
  const DETAIL = __DETAIL__, MAX_ROWS = __MAX_ROWS__, TARGETS = __TARGETS__;
  const seen = new Map(), originals = new WeakMap();
  let rows = [], counts = {}, busy = false;

  // The watch calls this through DevTools. A page has no way to reach the
  // handler of a Proxy, so it cannot find or call it.
  const drain = () => {
    const body = stringify({url: location.href, rows: rows, counts: counts});
    rows = []; counts = {};
    return body;
  };
  const hash = (text) => {
    let h = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) { h ^= text.charCodeAt(i); h = Math.imul(h, 0x01000193) >>> 0; }
    return ('0000000' + h.toString(16)).slice(-8);
  };
  const brief = (value, depth) => {
    if (value === null || value === undefined) return value === null ? null : '[undefined]';
    const kind = typeof value;
    if (kind === 'string') return value.length > 200 ? {length: value.length, fnv1a: hash(value), head: value.slice(0, 60)} : value;
    if (kind === 'number' || kind === 'boolean') return value;
    if (kind === 'function') return '[function ' + (value.name || '') + ']';
    if (kind !== 'object') return '[' + kind + ']';
    const name = Object.prototype.toString.call(value).slice(8, -1);
    if (ArrayBuffer.isView(value)) {
      let h = 0x811c9dc5;
      const n = Math.min(value.length || 0, 65536);
      for (let i = 0; i < n; i++) { h ^= (value[i] * 1000) | 0; h = Math.imul(h, 0x01000193) >>> 0; }
      return {type: name, length: value.length, fnv1a: ('0000000' + h.toString(16)).slice(-8)};
    }
    if (depth > 1) return '[' + name + ']';
    if (isArray(value)) return value.slice(0, 8).map((item) => brief(item, depth + 1));
    if (name === 'Object') {
      const out = {};
      let n = 0;
      for (const key in value) { if (n++ >= 12) break; try { out[key] = brief(value[key], depth + 1); } catch (e) {} }
      return out;
    }
    return '[' + name + ']';
  };
  const caller = () => {
    const stack = String(new ErrorCtor().stack || '').split('\n');
    for (let i = 1; i < stack.length; i++) {
      const found = /((?:https?|blob|file):[^\s)]+?):(\d+):(\d+)\)?$/.exec(stack[i]);
      if (found) {
        const named = /at (?:async )?([^\s(]+) \(/.exec(stack[i]);
        const frame = {url: found[1], line: +found[2], column: +found[3]};
        if (named) frame.function = named[1];
        return frame;
      }
    }
    return null;
  };
  const log = (api, quiet, args, result) => {
    if (busy) return;
    busy = true;
    try {
      const n = (seen.get(api) || 0) + 1;
      seen.set(api, n);
      counts[api] = (counts[api] || 0) + 1;
      if (!quiet && n <= DETAIL && rows.length < MAX_ROWS) {
        const row = {api: api, n: n, time: clock() / 1000, at: caller()};
        if (args && args.length) row.args = brief(Array.prototype.slice.call(args), 0);
        if (result !== undefined) row.result = brief(result, 0);
        rows.push(row);
      }
    } catch (e) {}
    busy = false;
  };
  // A Proxy keeps the name and length of what it wraps. Its toString()
  // would drop the name, so toString is answered for the original.
  const wrap = (fn, trap) => {
    trap.drain = drain;
    const proxy = new Proxy(fn, trap);
    originals.set(proxy, fn);
    return proxy;
  };
  const resolve = (path) => {
    let at = window;
    if (path === 'window') return at;
    for (const part of path.split('.')) { if (at == null) return null; at = at[part]; }
    return at;
  };
  for (const target of TARGETS) {
    let owner = null;
    try { owner = resolve(target.path); } catch (e) {}
    if (owner == null) continue;
    const prefix = target.path === 'window' ? '' : target.path.replace('.prototype', '') + '.';
    for (const member of target.members) {
      try {
        const d = describe(owner, member.name);
        if (!d || d.configurable === false) continue;
        const api = prefix + member.name, quiet = member.quiet;
        if (api === 'Function.toString') {
          d.value = wrap(d.value, {apply(fn, self, args) { log(api, quiet); return apply(fn, originals.get(self) || self, args); }});
        } else if (target.how === 'g') {
          if (typeof d.get !== 'function') continue;
          d.get = wrap(d.get, {apply(fn, self, args) { const r = apply(fn, self, args); log(api, quiet, null, r); return r; }});
        } else if (target.how === 'm') {
          if (typeof d.value !== 'function') continue;
          d.value = wrap(d.value, {apply(fn, self, args) { const r = apply(fn, self, args); log(api, quiet, args, r); return r; }});
        } else {
          if (typeof d.value !== 'function') continue;
          d.value = wrap(d.value, {construct(fn, args, target) { log(api, quiet, args); return construct(fn, args, target); }});
        }
        define(owner, member.name, d);
      } catch (e) {}
    }
  }
})();
"""


def hook_source() -> str:
    """The script to run before a page's own.

    It keeps its log to itself. This browser gives a page neither DevTools
    bindings nor console events an outside client can hear, so there is no
    channel for the page to push on. The watch pulls instead: it asks
    DevTools for the handler of one wrapped member, and calls `drain` on it.
    """
    return (
        _HOOK.replace("__DETAIL__", str(DETAIL))
        .replace("__MAX_ROWS__", str(MAX_ROWS))
        .replace("__TARGETS__", json.dumps(targets(), separators=(",", ":")))
    )


def rows_from_report(payload: str) -> list[dict]:
    """The lines to append to fingerprint.jsonl for one report from a page."""
    try:
        body = json.loads(payload)
    except (TypeError, ValueError):
        return []
    if not isinstance(body, dict):
        return []
    page = body.get("url") if isinstance(body.get("url"), str) else ""
    found: list[dict] = []
    for row in body.get("rows") or []:
        if isinstance(row, dict) and isinstance(row.get("api"), str):
            found.append({"page": page, **row})
    counts = body.get("counts")
    if isinstance(counts, dict) and counts:
        found.append({"page": page, "counts": {str(api): int(n) for api, n in counts.items() if isinstance(n, (int, float))}})
    return found


def read(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.is_file():
        return rows
    with path.open(encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    return rows


def summary(rows: list[dict]) -> dict:
    """Calls by API and by script, from the lines of fingerprint.jsonl."""
    apis: dict[str, dict] = {}
    scripts: dict[str, dict[str, int]] = {}
    for row in rows:
        for api, n in (row.get("counts") or {}).items():
            entry = apis.setdefault(api, {"api": api, "category": category_of(api), "count": 0, "pages": [], "scripts": [], "calls": []})
            entry["count"] += n
            if row.get("page") and row["page"] not in entry["pages"]:
                entry["pages"].append(row["page"])
        api = row.get("api")
        if not isinstance(api, str):
            continue
        entry = apis.setdefault(api, {"api": api, "category": category_of(api), "count": 0, "pages": [], "scripts": [], "calls": []})
        call = {key: row[key] for key in ("time", "args", "result", "at") if row.get(key) is not None}
        entry["calls"].append(call)
        frame = row.get("at") if isinstance(row.get("at"), dict) else None
        if frame and isinstance(frame.get("url"), str):
            if frame["url"] not in entry["scripts"]:
                entry["scripts"].append(frame["url"])
            seen = scripts.setdefault(frame["url"], {})
            seen[api] = seen.get(api, 0) + 1
    ordered = sorted(apis.values(), key=lambda item: (-item["count"], item["api"]))
    categories: dict[str, int] = {}
    for item in ordered:
        categories[item["category"]] = categories.get(item["category"], 0) + item["count"]
    return {
        "version": 1,
        "note": NOTE,
        "total": sum(item["count"] for item in ordered),
        "categories": dict(sorted(categories.items(), key=lambda pair: -pair[1])),
        "apis": ordered,
        "scripts": [
            {"url": url, "apis": dict(sorted(seen.items(), key=lambda pair: -pair[1]))}
            for url, seen in sorted(scripts.items(), key=lambda pair: -sum(pair[1].values()))
        ],
    }


def write_summary(out: Path) -> int | None:
    """Write fingerprint.json when the log exists. Returns the number of calls, or None."""
    rows = read(Path(out) / LOG_NAME)
    if not rows:
        return None
    body = summary(rows)
    dest = Path(out) / SUMMARY_NAME
    part = dest.with_name(dest.name + ".part")
    part.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    part.replace(dest)
    return body["total"]
