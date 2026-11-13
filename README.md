# Oby

Oby records a browser session as the browser sent it. One window, one local recorder, one optional upstream proxy, and a folder that holds the whole visit.

The browser is [invisible-playwright](https://github.com/oss-invisible/playwright), a patched Firefox. [mitmcloak](https://github.com/sardanioss/mitmcloak) mirrors that browser's TLS on the way out. Header order, casing, and repeated cookies stay in the recording. Scripted clicks follow a [Cursory](https://github.com/Vinyzu/cursory) path. An agent can drive the same browser.

Copyright (c) 2026 [mavroth](https://github.com/mavroth). Released under the MIT license.

Published Firefox engines are Windows x86_64 and Linux x86_64. On a Mac, Oby runs that Linux engine in Docker (`linux/amd64`). Docker Desktop has to be running. The first start builds an image and downloads the engine. The recording is still the `--out` folder on the Mac. A visible session opens in Screen Sharing. There is no password; the share listens on this machine only.

```bash
pip install -e .
oby --proxy 'http://user:pass@host:port' --out session --url https://example.com
```

The first launch downloads the Firefox engine (about 260 MB) and checks its sha256. Close the window, or press Ctrl+C. The file written at the end is `session/session.har`, a HAR 1.2 log. Header order, casing, and repeated cookies are the header arrays. Each entry's `_oby` object holds the HTTP/2 preface and the mitmcloak result. `session/scripts.json` is written beside it and lists the JavaScript that ran.

`session/` also holds:

| file | what |
| --- | --- |
| `session.har` | the recording, written when the session ends |
| `scripts.json` | the JavaScript that ran, written when the session ends |
| `flows.jsonl` | the same exchanges, written as they finish, which the HAR is built from |
| `scripts-live.jsonl` | eval, new Function, timers, and blob workers, written as they run |
| `flows.mitm` | the capture in mitmproxy's own format |
| `storage.json` | cookies and localStorage, from `oby browse` |
| `profile/` | the Firefox profile, so the next run is the same browser |
| `presets/` | TLS presets mitmcloak exported from this session |
| `meta.json` | when it ran, how many flows, the proxy host with the password removed |

The folder is a full session, including cookies. Treat it like a password.

## Proxy

Leave `--proxy` off and the origin is dialed directly, still through the recorder. `OBY_PROXY` is the same setting, so the password does not have to sit in a config file or on the Docker command line. The browser itself only talks to `http://127.0.0.1:<port>`. The upstream proxy is handed to mitmcloak.

On a Mac the browser runs in a container. A remote proxy hostname works as written. A proxy listening on the Mac is reached at `host.docker.internal` and the port. `127.0.0.1` inside the container is the container itself.

Firefox will not use a Chromium certificate flag. The context accepts the recorder's certificate, and the egress lookup trusts that CA together with the public roots. The lookup is how this browser picks a timezone from the address it actually leaves from.

## An agent drives the browser

`oby mcp` starts the same recorder, then runs [invisible-playwright-mcp](https://github.com/oss-invisible/playwright_mcp) on stdio. The agent's browser tools are that server's tools. The server is pointed at the recorder with `STEALTHFOX_PROXY=http://127.0.0.1:<port>`. On a Mac the default visible session opens in Screen Sharing. `oby mcp --headless` does not.

The server's instructions tell the agent how the recording works: the browser talks only to the local recorder, exchanges land in `flows.jsonl` while the visit goes on, and `session.har` and `scripts.json` are written when the client closes. The tool `oby_recording` returns that folder, both paths, and the counts. It does not return cookies, header values, or script source.

## JavaScript that ran

`scripts.json` holds every script Oby could see. A fetched `.js` file and an inline `<script>` come from the recording. `eval`, `new Function`, a string passed to `setTimeout` or `setInterval`, and a blob worker are reported by a hook that runs before the page. The hook watches the global `eval`, `Function`, `setTimeout`, `setInterval`, `Worker`, and `SharedWorker`.

[Ghostwire](https://github.com/sofianeelhor/ghostwire) records these same kinds on Chrome by listening to the debugger. This Firefox has no script-parsed debugger, so the hook is ordinary page JavaScript and a site can see it. The report is posted to `https://oby-scripts.invalid/collect`. The recorder answers that name itself, and the exchange is left out of the HAR. When the site's Content-Security-Policy would block the report, the browser also receives `connect-src` for that name. The saved header is the one the site sent.

`flows.jsonl` stores the block as `request_header_block`: order, casing, and repeated names. On HTTP/2 the preface is `http2.pseudo_order` and `http2.settings`. HTTP/2 lowercases names on the wire, so odd casing is an HTTP/1.1 property. The same preface is what mitmcloak replays upstream, in `presets/`. The HAR keeps that preface on `entry._oby.http2`.

Set `OBY_PROXY` in the environment when the origin should be reached through an upstream proxy. The first start downloads the engine before the server answers, so the client timeout is several minutes.

Agent clicks go through invisible-playwright-mcp's own tools, which move the pointer themselves. `click` and `type_text` in the Python API use Cursory, and the library's own pointer curves are off on that path so a move is not drawn twice.

```bash
oby mcp --out session
```

```python
from oby import Session

with Session(proxy="http://user:pass@host:port", out="session") as s:
    s.goto("https://example.com")
    s.click("a")                 # Cursory path, then a click
    s.type_text("input", "ada")  # click, then per-character delay
```

Your hand in the window is the interactive session. Cursory is only used by `click`, `move`, and `type_text`.

## License

Copyright (c) 2026 [mavroth](https://github.com/mavroth). This repository is MIT. See [LICENSE](LICENSE).

Cursory is LGPL-3.0-or-later and stays a dependency. The Firefox engine is MPL-2.0 and is downloaded by invisible-playwright, not shipped here. That package is MIT AND Apache-2.0 because it vendors a Playwright client. Those projects keep their own licenses.
