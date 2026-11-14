---
name: oby
description: Records a stealth Firefox session as a HAR, including the JavaScript that ran, through an optional upstream proxy. Use when recording a browser visit, writing session.har or scripts.json, running oby browse or oby mcp, or invoking /oby.
license: MIT
compatibility: Python 3.11 or newer. On macOS, Docker Desktop must be running so Oby can use the published Linux x86_64 Firefox engine. Install the oby program separately from this skill.
metadata:
  author: mavroth
  version: "0.1.0"
  short-description: Record a stealth Firefox session as a HAR
---

# Oby

Oby records one Firefox session as the browser sent it. This skill is version 0.1.0 of https://github.com/mavroth/oby. The installable version is the git tag.

## Install this skill

```bash
npx skills add mavroth/oby@v0.1.0 --skill oby
```

`npx skills add mavroth/oby --skill oby` follows the default branch. A later release is the same command with that release's tag.

## Install the program

```bash
git clone https://github.com/mavroth/oby
cd oby
pip install -e .
```

The first start downloads the Firefox engine, about 260 MB, and checks its sha256. On a Mac that download happens inside Docker (`linux/amd64`). Leave Docker Desktop running. Do not look for a macOS engine and do not start the container yourself. `oby` does that.

## Which command

The person drives the window:

```bash
oby browse --url https://example.com --out session
```

An agent drives the same browser. Start an MCP server on stdio:

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

Add `--headless` when no window should appear. On a Mac a visible session opens in Screen Sharing. The share has no password and listens on this machine only.

An upstream proxy is `OBY_PROXY`, set in the environment that launches `oby`. Do not put a proxy URL that contains a password on the command line, in MCP config, or in chat. The browser talks only to the local recorder. Do not start another proxy, and do not browse to the recorder's port. No tool can change the proxy after launch.

Give the first `oby mcp` start several minutes. The engine download finishes before the server answers.

## While the agent is connected

1. Call `browser_open` before any other browser tool. With no arguments it restores the seed, proxy, and profile for this process.
2. Go where you were asked.
3. Call `oby_recording` for the folder, `session.har`, `scripts.json`, and the counts. A client may prefix the tool name.
4. Close the MCP client. That write produces `session.har` and `scripts.json`. Until then, exchanges are in `flows.jsonl`.

`oby_recording` returns paths and counts. It does not return cookies, header values, or script source. Leave those in the folder. Do not print them, the proxy password, or the egress address. Treat the output folder like a password.

`oby browse` also writes `storage.json` (cookies and localStorage) when the window closes. `oby mcp` does not.

## What was recorded

`session.har` is a HAR 1.2 log. Header order is the header arrays. Each entry's `_oby` object holds the HTTP/2 preface and the mitmcloak result.

`scripts.json` is the Firefox counterpart of the script list [Ghostwire](https://github.com/sofianeelhor/ghostwire) records on Chrome: every script the engine parsed, read from the debugger, with nothing injected into the page. It includes fetched files, inline scripts, `eval`, `new Function`, a string passed to `setTimeout` or `setInterval`, a blob worker, a dedicated worker loaded from its own URL, and a script inserted into the page. The listener is Firefox's remote debugger on loopback. It does not pause the page. `zoom.stealth.debugger.force_detach` is turned off so those scripts are reported. A page cannot read that preference. Attaching can change how the engine compiles a script. If the listener does not start, a page hook is the fallback and a site can see it. The hook's collector exchange is not a HAR entry.

The repository README is the long description of every file in the folder.
