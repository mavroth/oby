# Oby

Oby records a browser session as the browser sent it. One window, one local recorder, one optional upstream proxy, and a folder that holds the whole visit.

The browser is [invisible-playwright](https://github.com/oss-invisible/playwright), a patched Firefox. [mitmcloak](https://github.com/sardanioss/mitmcloak) mirrors that browser's TLS on the way out. Header order, casing, and repeated cookies stay in the recording. Scripted clicks follow a [Cursory](https://github.com/Vinyzu/cursory) path. An agent can drive the same browser.

Copyright (c) 2026 [mavroth](https://github.com/mavroth). Released under the MIT license.

Published Firefox engines are Windows x86_64 and Linux x86_64. On a Mac, Oby runs that Linux engine in Docker (`linux/amd64`). Docker Desktop has to be running. The first start builds an image and downloads the engine. The recording is still the `--out` folder on the Mac. A visible session opens in Screen Sharing. There is no password; the share listens on this machine only.

```bash
pip install -e .
oby --proxy 'http://user:pass@host:port' --out session --url https://example.com
```

The first launch downloads the Firefox engine (about 260 MB) and checks its sha256. Close the window, or press Ctrl+C. `session/` then holds:

| file | what |
| --- | --- |
| `flows.jsonl` | every exchange: ordered headers, bodies, status, the mitmcloak preset used |
| `flows.mitm` | the same capture in mitmproxy's own format |
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

`flows.jsonl` stores the block as `request_header_block`: order, casing, and repeated names. On HTTP/2 the preface is `http2.pseudo_order` and `http2.settings`. HTTP/2 lowercases names on the wire, so odd casing is an HTTP/1.1 property. The same preface is what mitmcloak replays upstream, in `presets/`.

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
