# Oby

Oby records a browser session as the browser sent it.

You get one Firefox window, one local recorder, and a folder. The folder holds a HAR of the traffic, every script Firefox parsed, the cookies, and the profile. An upstream proxy is optional. You can drive the window yourself, or hand the same browser to an agent.

The browser is [invisible-playwright](https://github.com/oss-invisible/playwright), a patched Firefox. [mitmcloak](https://github.com/sardanioss/mitmcloak) mirrors that browser's TLS on the way out, so header order and the HTTP/2 preface stay intact. Scripted clicks in the Python API follow a [Cursory](https://github.com/Vinyzu/cursory) path.

[Ghostwire](https://github.com/sofianeelhor/ghostwire) instruments Chrome from the debugger and records every script the engine parses, including `eval`, `new Function`, and workers, with nothing injected into the page. Oby records that same script list on Firefox.

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

On a Mac, start Docker Desktop first. Oby runs the published Linux Firefox engine there. The same commands run on Linux and Windows without that image.

## How a visit runs

`oby browse` opens the window and records into `--out` (`session/` when you leave it off). `oby mcp` records the same browser for an agent and writes the HAR when the client closes.

Firefox's own startup requests are saved first. The page you asked for follows. On a Mac the engine is starting in Docker, so that page can be about half a minute after the first line in `flows.jsonl`. A folder that only shows Firefox hosts in that window still has the visit ahead of it. `scripts.json` is written when the session ends.

Each launch clears `flows.jsonl`, `scripts-parsed.jsonl`, `scripts-live.jsonl`, `scripts.json`, and `session.har` in that folder, then records this visit. The profile stays, so the next run is the same browser.

The document waits at most 8 seconds so the debugger is listening before a dedicated worker starts. The browser then sends its own request.

## For an agent

Install the instructions for this release:

```bash
npx skills add mavroth/oby@v0.1.0 --skill oby
```

`npx skills add mavroth/oby --skill oby` follows the default branch. The skill is [`skills/oby/SKILL.md`](skills/oby/SKILL.md). It tells an agent how to run `oby browse` and `oby mcp`, and which files to keep.

Published Firefox engines are Windows x86_64 and Linux x86_64. On a Mac, Oby runs that Linux engine in Docker (`linux/amd64`). Docker Desktop has to be running. The first start builds an image and downloads the engine, about 260 MB, and checks its sha256. The recording stays in the `--out` folder on the Mac. A visible session opens in Screen Sharing. The share has no password and listens on this machine only.

## What you get

| file | what |
| --- | --- |
| `session.har` | HAR 1.2 of the visit, written when the session ends |
| `scripts.json` | every script Firefox parsed, written when the session ends |
| `flows.jsonl` | the same exchanges, written as they finish |
| `scripts-parsed.jsonl` | each script as Firefox parsed it |
| `scripts-live.jsonl` | the page-hook reports, only if the debugger did not start |
| `flows.mitm` | the capture in mitmproxy's own format |
| `storage.json` | cookies and localStorage, from `oby browse` |
| `profile/` | the Firefox profile, so the next run is the same browser |
| `presets/` | TLS presets mitmcloak exported from this session |
| `meta.json` | when it ran, how many flows, the proxy host with the password removed |

The folder is a full session, including cookies and script source. Treat it like a password.

Header order, the original casing, and repeated `Cookie` headers are the header arrays in the HAR. Each entry's `_oby` object holds the HTTP/2 preface (`pseudo_order`, `settings`) and the mitmcloak result. HTTP/2 lowercases names on the wire, so odd casing is an HTTP/1.1 property. The same preface is what mitmcloak replays upstream, in `presets/`.

## JavaScript that ran

This is the Firefox counterpart of Ghostwire's script list. The debugger reports each script as the engine parses it. The page is not given a hook to do it.

`scripts.json` is that list, taken from `scripts-parsed.jsonl`. The source is the engine's copy, so a fetched file is stored whole even when the saved response body is shorter.

- a fetched script file
- an inline `<script>`, and a script inserted into the page
- `eval`, `new Function`, and a string passed to `setTimeout` or `setInterval`
- a blob worker
- a dedicated worker loaded from its own URL

The listener is Firefox's remote debugger on `127.0.0.1`. It does not pause the page and it sets no breakpoints. This engine normally ignores that debugger (`zoom.stealth.debugger.force_detach`). Oby turns the preference off so the parsed scripts are reported. A page cannot read the preference. Attaching can change how the engine compiles a script.

If the debugger does not start, Oby falls back to a page hook. The hook watches the global `eval`, `Function`, `setTimeout`, `setInterval`, `Worker`, and `SharedWorker`, and a site can see it. The report is posted to `https://oby-scripts.invalid/collect`. The recorder answers that name itself, and that exchange stays out of the HAR. When the site's Content-Security-Policy would block the report, the browser also receives `connect-src` for that name. The header saved in the HAR is the one the site sent. A live debugger leaves that header alone.

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

The server's instructions tell the agent how the recording works. Exchanges land in `flows.jsonl` during the visit. Firefox's own startup traffic is written first, and the page follows. `session.har` and `scripts.json` are written when the client closes. The tool `oby_recording` returns the folder, both paths, and the counts. It returns none of the cookies, header values, or script source.

The browser tools change the page, so an assistant confirms each one until the server is allowed. [`.claude/settings.json`](.claude/settings.json) allows every tool on the `oby` server. Claude Code and Grok read that file. The first time you open the project, trust the folder. That question is the only one. After it, the agent opens the browser, navigates, and clicks without asking again. If a client still offers a choice on one tool, choose always allow for `oby`.

The first start downloads the engine before the server answers, so give the client several minutes. Set `OBY_PROXY` when the origin should be reached through an upstream proxy.

Agent clicks go through invisible-playwright-mcp's own tools, which move the pointer themselves. The library's own pointer curves are off on the Python `click` and `type_text` path, so a move is not drawn twice.

## License

Copyright (c) 2026 [mavroth](https://github.com/mavroth). This repository is MIT. See [LICENSE](LICENSE).

Cursory is LGPL-3.0-or-later and stays a dependency. The Firefox engine is MPL-2.0 and is downloaded by invisible-playwright, not shipped here. That package is MIT AND Apache-2.0 because it vendors a Playwright client. Those projects keep their own licenses.
