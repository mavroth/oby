# Oby

Oby records a browser session as the browser sent it.

You get one browser window, one local recorder, and a folder. The folder holds a HAR of the traffic, every script the engine parsed, the cookies, and the profile. An upstream proxy is optional. You can drive the window yourself, or hand the same browser to an agent.

The browser is [CloakBrowser](https://github.com/CloakHQ/CloakBrowser), a patched Chromium that runs on your machine. [mitmcloak](https://github.com/sardanioss/mitmcloak) mirrors that browser's TLS on the way out, so header order and the HTTP/2 preface stay intact. Scripted clicks in the Python API follow a [Cursory](https://github.com/Vinyzu/cursory) path.

[Ghostwire](https://github.com/sofianeelhor/ghostwire) records every script Chrome parses, including `eval`, `new Function`, and workers, with nothing injected into the page. Oby records that script list too, next to the traffic. The record is the source of each script the engine parsed. Function hooks, resolved runtime values, and heap search stay in Ghostwire.

Copyright (c) 2026 [mavroth](https://github.com/mavroth). Released under the MIT license.

## Install

Python 3.11 or newer. CloakBrowser publishes its Chromium for macOS, Linux, and Windows, and the first start downloads it into `~/.cloakbrowser`. Oby is tested on an Apple Silicon Mac. Oby uses CloakBrowser 0.6, the last release whose free browser starts without a license key.

```bash
git clone https://github.com/mavroth/oby
cd oby
pip install -e .
oby --url https://example.com
```

`oby` with no subcommand is `oby browse`. Close the window, or press Ctrl+C. Oby writes `session/session.har` and `session/scripts.json`.

An agent follows [An agent](#an-agent). The installable instructions are `npx skills add mavroth/oby@v0.3.0 --skill oby`.

## Commands

| goal | command |
| --- | --- |
| Open a window on a page | `oby browse --url https://example.com --out session` |
| Same visit, no window | `oby browse --headless --url https://example.com --out session` |
| Let an agent drive | `oby mcp --out session` |
| Agent, no window | `oby mcp --headless --out session` |
| Leave through an upstream proxy | `OBY_PROXY='http://user:pass@host:port' oby browse --url https://example.com` |
| Also log the fingerprinting APIs a page calls | `oby browse --fingerprints --url https://example.com` |
| Write a readable copy of each recorded script | `oby deobfuscate --out session` |

`--out` defaults to `session`. `--proxy` is the same setting as `OBY_PROXY`. Prefer the environment variable. The password then stays out of the command line.

## How a visit runs

The browser's own startup requests, if it makes any, are saved first. The page you asked for follows.

Each launch starts `--out` empty and records this visit. The previous visit is moved to `history/<when it began>/`, with its HAR, scripts, and logs. A previous launch that recorded no exchange is removed. Nothing is deleted from `history/`, so remove old visits yourself. The profile stays, so the next run is the same browser.

`session.har` and `scripts.json` are written when the window closes, or when the MCP client closes. Until then the exchanges are in `flows.jsonl`.

## What you get

| file | what |
| --- | --- |
| `session.har` | HAR 1.2 of the visit, written when the session ends |
| `scripts.json` | every script the engine parsed, written when the session ends |
| `flows.jsonl` | the same exchanges, written as they finish |
| `ws.jsonl` | each WebSocket message and close, written as it happens |
| `scripts/` | each script's source as `<sha256>.js`, and each WebAssembly module as `<sha256>.wasm`, written with `scripts.json` |
| `fingerprint.json` | the fingerprinting APIs each page called, by API and by script. Only with `--fingerprints` |
| `fingerprint.jsonl` | the same calls, written during the visit |
| `scripts-parsed.jsonl` | each script as the engine parsed it |
| `initiators.jsonl` | every request the browser made and what started it, as the browser reported it |
| `flows.mitm` | the capture in mitmproxy's own format, without the bodies of streamed responses |
| `storage.json` | cookies and localStorage, written when the browser closes |
| `history/` | earlier visits recorded into this folder |
| `chrome-profile/` | the browser profile, so the next run is the same browser |
| `presets/` | TLS presets mitmcloak exported from this session |
| `meta.json` | when it ran, how many flows, the request coverage, the proxy host with the password removed |

The folder is a full session, including cookies and script source. Treat it like a password.

### Everything that was sent

Bodies are kept whole, in both directions, and so is every script. A recording of a large download is as large as the download. `OBY_MAX_BODY`, a number of bytes, cuts each body there and marks the entry `_oby.truncated`.

A response is passed to the page as it arrives, through the same mitmcloak session and headers as before, so a page that reads a stream sees it as it would without the recorder. A server may take five minutes to start answering, which is the browser's own limit. Two cases still go the older way, where the response reaches the browser only when it is complete and within 30 seconds: a request whose body is not text, and a `HEAD`. When the origin speaks HTTP/1.1, httpcloak ends a response after 60 seconds. Over HTTP/2 it stays open as long as the origin sends.

A request that asks for `text/event-stream` also gets `_oby.events`, the body split into events with the `time` each one arrived, and `_oby.stream`, which says whether the stream ended or was still open when the session closed.

A WebSocket is recorded message by message. The messages are `_webSocketMessages` on the handshake entry, the field Chrome writes, with `type` (`send` or `receive`), `time`, `opcode`, and `data`. A binary message is base64 and says `_encoding`. `_oby.websocket` is how the socket closed. mitmcloak does not carry WebSockets, so that one connection reaches the origin with mitmproxy's TLS and not the browser's.

`timings` has `send`, `wait`, and `receive`. `wait` on a mitmcloak exchange is the whole upstream round trip. `connect` and `ssl` are filled when the recorder opened the origin connection for that exchange, which is the WebSocket case. `_oby.timing` holds every clock reading in epoch seconds, including when the browser connected to the recorder and finished TLS.

`_oby.initiator` is what started the request: its `type` (`document`, `script`, `xhr`, `fetch`, and so on), and for a request made from JavaScript the `url`, `line`, `column`, and `function` of the frame that made it. A request made after an `await` or a timer names the frame that was waiting and says `async`. `_initiator` is the same frame in Chrome's form, where lines and columns count from 0. The browser reports this, with nothing injected into the page. A request is matched to its exchange by method and URL, in order.

`meta.json` has `coverage`: the browser's own list of the requests it made, checked against the exchanges. `missing` is a request the browser got an answer to that has no exchange, and it should be empty. `from_cache` counts requests the browser answered from its cache, which never reach the wire. `unanswered` lists requests the browser dropped before an answer, as a page does to its pending requests when it navigates away. A request the session ended on is an exchange with no status and an `error`.

Each top-level navigation starts a new page in `pages`, and a redirect stays on the page it began.

### See what loaded

This prints the status and the URL without the query string. Headers, cookies, and bodies stay in the file.

```bash
python -c '
import json
from pathlib import Path
from urllib.parse import urlsplit
for line in Path("session/flows.jsonl").read_text().splitlines():
    row = json.loads(line)
    url = urlsplit(row["url"])
    print(row.get("status"), f"{url.scheme}://{url.netloc}{url.path}")
'
```

When the session has ended, print the script counts. `source` stays in the file.

```bash
python -c 'import json; print(json.load(open("session/scripts.json"))["counts"])'
```

`counts` is how many scripts of each kind were kept: `network`, `inline`, `eval`, `function`, `timer`, `blob`, `wasm`. Each script has `kind`, `url`, `sha256`, `length`, `count`, and `source`. `truncated` is set when the source was cut. `from` is `wire` when the text is the recorded response body and not the engine's copy. That happens when the engine named the script and the page closed before its text was read, and when a file was fetched to run (`Sec-Fetch-Dest: script` or a worker) and the engine never named it. The second kind also says `reported: false`. A preload the page never used is the one case where such a file did not run. `note` says whether the list came from the engine or, when the DevTools watch did not attach, from the recording alone.

Header order, the original casing, and repeated `Cookie` headers are the header arrays in the HAR. Each entry's `_oby` object holds the HTTP/2 preface (`pseudo_order`, `settings`) and the mitmcloak result. HTTP/2 lowercases names on the wire, so odd casing is an HTTP/1.1 property. The same preface is what mitmcloak replays upstream, in `presets/`.

## JavaScript that ran

`scripts.json` is the list of scripts the engine parsed, taken from `scripts-parsed.jsonl`. The source is the engine's copy, so a fetched file is stored whole even when the saved response body is shorter.

- a fetched script file
- an inline `<script>`, and a script inserted into the page
- `eval`, `new Function`, and a string passed to `setTimeout` or `setInterval`
- a blob worker
- a worker loaded from its own URL
- a WebAssembly module

The listener is a DevTools client on a loopback port chosen at launch. It attaches to every page, frame, and worker, and turns on two domains: Debugger, which names each script V8 parses and hands over its source, and Network, which lists each request and the frame that made it. `debugger` statements are skipped, so a page that uses them against DevTools is not paused. Nothing is injected into the page, unless you ask for the fingerprint log below.

A WebAssembly module has no source. It is listed with its `length` in bytes, the names it `imports` from the page and `exports` to it, and how many `functions` it defines, and its bytes are `scripts/<sha256>.wasm`. V8 does not say whether a script with no URL came from `eval`, `new Function`, or a string timer. Oby tells `new Function` by its source and lists a string timer as `eval`.

The text of an `eval` or a `new Function` exists only in the engine. Oby asks for those ahead of fetched files, which can be read back from the recording. One that is parsed in the last moment before a page leaves can still be missed.

What Playwright itself evaluates in the page, and what an agent runs with `browser_evaluate`, is left out of the list.

## Reading a script

A recorded script is often minified or obfuscated. `oby deobfuscate --out session` writes a readable copy of each one as `scripts/<sha256>.deob.js`, beside the original, which is never changed. The agent tool `oby_script` returns the same views on request: `source`, `pretty`, and `deobfuscated`.

`pretty` is the same code reformatted, one statement to a line. `deobfuscated` also undoes the spelling an obfuscator uses, and each rewrite keeps what the code does:

| written as | becomes |
| --- | --- |
| `'\x68\x69'`, `'\u0068i'` | `'hi'` |
| `0x1f` | `31` |
| `!![]`, `![]`, `!0`, `!1`, `void 0` | `true`, `false`, `true`, `false`, `undefined` |
| `obj['name']` | `obj.name` |
| `'ab' + 'cd'` | `'abcd'` |
| `names[3]`, where `names` is a list of strings only ever read by a fixed index | the string |

Nothing is executed. So the two things that need execution are left as they are: a string table the script rotates and reads through a decoder function, which is what obfuscator.io produces, and flattened control flow. If the [`webcrack`](https://github.com/j4k0xb/webcrack) program is on your `PATH`, Oby uses it for the `deobfuscated` view instead, since it handles those. Oby does not download it.

Search works on any view. `oby_scripts` finds text, or a regular expression, across every script, and searches a WebAssembly module by its import and export names. `oby_script` with `find` returns the matching lines of one script with their line numbers. Search the `pretty` or `deobfuscated` view, where a line is one statement.

## Fingerprinting APIs

`--fingerprints`, or `OBY_FINGERPRINTS=1`, also records which fingerprinting APIs each page calls, and from which script. It is off by default, because it is the one thing Oby puts in the page: a script that runs before the page's own and wraps those APIs. A wrapper answers `toString()` as the native function does, leaves no global behind, and sends nothing. A script that looks hard enough can still find it, so a site may behave differently with this on. Record without it when the recording itself must be clean.

| category | what is watched |
| --- | --- |
| `canvas` | `toDataURL`, `toBlob`, `getContext`, `getImageData`, `measureText`, `fillText`, and the same on an offscreen canvas |
| `webgl` | `getParameter`, `getExtension`, `getSupportedExtensions`, `getShaderPrecisionFormat`, `readPixels`, and WebGPU adapter requests |
| `audio` | creating an audio context, oscillators, compressors, analysers, `startRendering`, `getChannelData` |
| `navigator` | user agent, platform, hardware concurrency, device memory, languages, plugins, `webdriver`, touch points, client hints, connection, battery, keyboard layout |
| `screen` | screen size and colour depth, window size and position, `devicePixelRatio`, `matchMedia` |
| `fonts` | `document.fonts.check`, and element size reads, which is how installed fonts are measured |
| `locale` | `Intl` resolved options, timezone offset |
| `media` | `canPlayType`, `isTypeSupported`, `enumerateDevices`, media capabilities, speech voices |
| `permissions` | `permissions.query`, `Notification.permission` |
| `webrtc` | creating a peer connection, data channels, offers |
| `storage` | `localStorage` and `sessionStorage`, `document.cookie`, IndexedDB, storage estimates |
| `runtime` | `Function.prototype.toString`, `performance.now` and `performance.memory`, visibility and focus, workers, `WebAssembly.instantiate`, property descriptor reads |
| `sensors` | motion and orientation events, battery, Bluetooth, USB, HID |

`fingerprint.json` lists each API with how many times it was called, the scripts that called it, and its first 20 calls in each page: the arguments, a short form of what came back, and the file, line, and function that called. A long result, such as a canvas image or an audio buffer, is kept as its length and an FNV-1a hash, so two visits can be compared. The APIs a page calls thousands of times (timers, layout reads, storage, `toString`) are counted without their callers.

This browser gives a page no channel to report on: no DevTools bindings and no console events an outside client can hear. So the page keeps the log and Oby reads it, through DevTools, about once a second, and once more when a navigation begins, so a page that fingerprints and redirects does not take its log with it. Calls made inside a worker are not seen, and neither are the calls of a document that began before Oby attached to a new tab.

## Proxy

Leave `--proxy` off and the origin is dialed directly, still through the recorder. The browser itself only talks to `http://127.0.0.1:<port>`. The upstream proxy is handed to mitmcloak.

```bash
OBY_PROXY='http://user:pass@host:port' oby --url https://example.com
```

Chrome is given the recorder's certificate by its public key (`--ignore-certificate-errors-spki-list`). It then accepts a chain that holds that key, for every host, including those on its HSTS list, and still refuses any other bad certificate. A site on this machine goes through the recorder too.

## From Python

`oby browse` opens the window. Your hand is the interactive session. Cursory is only used by `click`, `move`, and `type_text`.

```python
from oby import Session

with Session(proxy="http://user:pass@host:port", out="session") as s:
    s.goto("https://example.com")
    s.click("a")                 # Cursory path, then a click
    s.type_text("input", "ada")  # click, then per-character delay
```

`s.page` and `s.context` are Playwright's.

## An agent

`oby mcp` is an MCP server on stdio. It starts the recorder and the browser in the same process and answers in about a second. `oby mcp --headless` hides the window.

```bash
oby mcp --out session
```

```json
{
  "mcpServers": {
    "oby": {
      "command": "oby",
      "args": ["mcp", "--out", "session"]
    }
  }
}
```

Install the instructions for this release:

```bash
npx skills add mavroth/oby@v0.3.0 --skill oby
```

`npx skills add mavroth/oby --skill oby` follows the default branch. The skill is [`skills/oby/SKILL.md`](skills/oby/SKILL.md). It tells an agent how to run `oby browse` and `oby mcp`, and which files to keep.

The browser tools are Playwright's, on the browser CloakBrowser opened, with that library's human-shaped pointer and typing.

Every tool that changes the page returns the page as it is afterwards: its URL and title, any dialog or new tab that came up, and a tree in which each element has a ref such as `e12`. The agent passes that ref to the next tool, so one call does the action and shows the result. An element inside an iframe or shadow DOM has a ref like any other. A page whose tree is longer than 20,000 characters is returned as its controls, links, and headings, and `browser_snapshot` gives the whole tree.

| tool | does |
| --- | --- |
| `browser_open`, `browser_close` | open or close the browser |
| `browser_navigate`, `browser_back` | load a URL, go back |
| `browser_snapshot` | the page as a tree with a ref on each element. `interactive` keeps only controls, links, and headings |
| `browser_click`, `browser_hover` | click or point at an element, by ref or CSS selector. A click also picks a dropdown option |
| `browser_type` | set a field of any kind to a value |
| `browser_fill_form` | set several fields in one call |
| `browser_select_option`, `browser_upload_files` | choose dropdown options, set a file input |
| `browser_click_at`, `browser_press_key`, `browser_scroll` | a point on the page, a key, scrolling |
| `browser_handle_dialog` | say whether the next alert, confirm, or prompt is accepted or dismissed |
| `browser_read_text`, `browser_read_html`, `browser_take_screenshot` | read the page |
| `browser_evaluate` | run JavaScript in the page |
| `browser_wait`, `browser_tabs` | wait for text or time, list and switch tabs |

`browser_type` sets each kind of field the way it takes a value. A text field, a textarea, or a rich-text editor is clicked and typed into key by key. A date, time, or colour input is set to the value whole, because typing digits into a picker gives a wrong value. A slider is set to its number. A dropdown takes the label of the option, and a checkbox takes `true` or `false`.

A dialog never blocks the page. It is accepted, unless `browser_handle_dialog` said to dismiss it, and the next result says what it asked and how it was answered. A link that opens a new tab moves the agent to that tab.

An element more than a screen away is scrolled near at once, and the pointer then moves to it as a person's would.

The server's instructions tell the agent how the recording works. Exchanges land in `flows.jsonl` during the visit. `session.har` and `scripts.json` are written when the client closes. The tool `oby_recording` returns the folder, both paths, and the counts. It returns none of the cookies, header values, or script source.

The agent can read the recording while the visit runs:

| tool | returns |
| --- | --- |
| `oby_exchanges` | the exchanges so far, filtered by host, method, status, or text, without bodies, each with the script frame that made it |
| `oby_exchange` | one exchange: headers in wire order, both bodies, timing, the HTTP/2 preface |
| `oby_messages` | the WebSocket messages of one handshake exchange |
| `oby_scripts` | the scripts and WebAssembly modules so far, and where a piece of text or a regular expression occurs in them |
| `oby_script` | one script: a slice of it, or the lines that match, as recorded, reformatted, or deobfuscated |
| `oby_fingerprint` | the fingerprinting APIs the page called and the scripts that called them, with `--fingerprints` |
| `oby_save` | writes `session.har`, `scripts.json`, `scripts/`, and `storage.json` now, and returns counts |

`oby_exchange`, `oby_messages`, `oby_scripts`, and `oby_script` return what the site and the browser sent, cookies and tokens included. That content then sits in the agent's conversation.

The browser tools change the page, so an assistant confirms each one until the server is allowed. [`.claude/settings.json`](.claude/settings.json) allows every tool on the `oby` server. Claude Code and Grok read that file. The first time you open the project, trust the folder. That question is the only one. After it, the agent opens the browser, navigates, and clicks without asking again. If a client still offers a choice on one tool, choose always allow for `oby`.

Set `OBY_PROXY` when the origin should be reached through an upstream proxy.

## License

Copyright (c) 2026 [mavroth](https://github.com/mavroth). This repository is MIT. See [LICENSE](LICENSE).

CloakBrowser's wrapper is MIT, and it downloads its Chromium build, which is not shipped here. Cursory is LGPL-3.0-or-later and stays a dependency. Those projects keep their own licenses.
