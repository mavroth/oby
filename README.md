# Oby

Oby records a browser session as the browser sent it.

You get one Firefox window, one local recorder, and a folder. The folder holds a HAR of the traffic, the JavaScript that ran, the cookies, and the profile. An upstream proxy is optional. You can drive the window yourself, or hand the same browser to an agent.

The browser is [invisible-playwright](https://github.com/oss-invisible/playwright), a patched Firefox. [mitmcloak](https://github.com/sardanioss/mitmcloak) mirrors that browser's TLS on the way out, so header order and the HTTP/2 preface stay intact. Scripted clicks in the Python API follow a [Cursory](https://github.com/Vinyzu/cursory) path.

Copyright (c) 2026 [mavroth](https://github.com/mavroth). Released under the MIT license.

## Install

Python 3.11 or newer.

```bash
git clone https://github.com/mavroth/oby
cd oby
pip install -e .
oby --url https://example.com
```

Close the window, or press Ctrl+C. Oby writes `session/session.har` and `session/scripts.json`.

Published Firefox engines are Windows x86_64 and Linux x86_64. On a Mac, Oby runs that Linux engine in Docker (`linux/amd64`). Docker Desktop has to be running. The first start builds an image and downloads the engine, about 260 MB, and checks its sha256. The recording stays in the `--out` folder on the Mac. A visible session opens in Screen Sharing. The share has no password and listens on this machine only.

## What you get

| file | what |
| --- | --- |
| `session.har` | HAR 1.2 of the visit, written when the session ends |
| `scripts.json` | the JavaScript that ran, written when the session ends |
| `flows.jsonl` | the same exchanges, written as they finish |
| `scripts-live.jsonl` | `eval`, `new Function`, timers, and blob workers, written as they run |
| `flows.mitm` | the capture in mitmproxy's own format |
| `storage.json` | cookies and localStorage, from `oby browse` |
| `profile/` | the Firefox profile, so the next run is the same browser |
| `presets/` | TLS presets mitmcloak exported from this session |
| `meta.json` | when it ran, how many flows, the proxy host with the password removed |

The folder is a full session, including cookies and script source. Treat it like a password.

Header order, the original casing, and repeated `Cookie` headers are the header arrays in the HAR. Each entry's `_oby` object holds the HTTP/2 preface (`pseudo_order`, `settings`) and the mitmcloak result. HTTP/2 lowercases names on the wire, so odd casing is an HTTP/1.1 property. The same preface is what mitmcloak replays upstream, in `presets/`.

## JavaScript that ran

`scripts.json` lists the scripts Oby could see:

- a fetched script file, and an inline `<script>`, taken from the recording
- `eval`, `new Function`, a string passed to `setTimeout` or `setInterval`, and a blob worker, reported by a hook that runs before the page

The hook watches the global `eval`, `Function`, `setTimeout`, `setInterval`, `Worker`, and `SharedWorker`.

[Ghostwire](https://github.com/sofianeelhor/ghostwire) records these same kinds on Chrome by listening to the debugger. This Firefox has no script-parsed debugger, so the hook is ordinary page JavaScript and a site can see it. The report is posted to `https://oby-scripts.invalid/collect`. The recorder answers that name itself, and that exchange stays out of the HAR. When the site's Content-Security-Policy would block the report, the browser also receives `connect-src` for that name. The header saved in the HAR is the one the site sent.

## Proxy

Leave `--proxy` off and the origin is dialed directly, still through the recorder. The browser itself only talks to `http://127.0.0.1:<port>`. The upstream proxy is handed to mitmcloak.

```bash
oby --proxy 'http://user:pass@host:port' --url https://example.com
```

`OBY_PROXY` is the same setting. The password then stays out of the command line and out of `docker ps`.

On a Mac the browser runs in a container. A remote proxy hostname works as written. A proxy listening on the Mac is reached at `host.docker.internal` and the port. `127.0.0.1` inside the container is the container itself.

Firefox accepts the recorder's certificate on the browser context. The egress lookup, which picks the timezone from the address the browser actually leaves from, trusts that CA together with the public roots.

## Drive the window

`oby browse` opens the window. Your hand is the interactive session. Cursory is only used by `click`, `move`, and `type_text`.

```bash
oby browse --headless --url https://example.com --out session
```

```python
from oby import Session

with Session(proxy="http://user:pass@host:port", out="session") as s:
    s.goto("https://example.com")
    s.click("a")                 # Cursory path, then a click
    s.type_text("input", "ada")  # click, then per-character delay
```

## An agent

`oby mcp` starts the same recorder, then runs [invisible-playwright-mcp](https://github.com/oss-invisible/playwright_mcp) on stdio. The agent's browser tools are that server's tools. On a Mac the default session is visible and opens in Screen Sharing. `oby mcp --headless` does not.

```bash
oby mcp --out session
```

The server's instructions tell the agent how the recording works. Exchanges land in `flows.jsonl` during the visit. `session.har` and `scripts.json` are written when the client closes. The tool `oby_recording` returns the folder, both paths, and the counts. It returns none of the cookies, header values, or script source.

The first start downloads the engine before the server answers, so give the client several minutes. Set `OBY_PROXY` when the origin should be reached through an upstream proxy.

Agent clicks go through invisible-playwright-mcp's own tools, which move the pointer themselves. The library's own pointer curves are off on the Python `click` and `type_text` path, so a move is not drawn twice.

## License

Copyright (c) 2026 [mavroth](https://github.com/mavroth). This repository is MIT. See [LICENSE](LICENSE).

Cursory is LGPL-3.0-or-later and stays a dependency. The Firefox engine is MPL-2.0 and is downloaded by invisible-playwright, not shipped here. That package is MIT AND Apache-2.0 because it vendors a Playwright client. Those projects keep their own licenses.
