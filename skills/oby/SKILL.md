---
name: oby
description: Records a stealth browser session as a HAR, including the JavaScript that ran, through an optional upstream proxy. Use when recording a browser visit, writing session.har or scripts.json, running oby browse or oby mcp, or invoking /oby. The browser is a patched Chromium on this machine. Read hosts and script counts, and leave cookies, headers, and script source in the folder.
license: MIT
compatibility: Python 3.11 or newer. The browser runs on the machine itself. Install the oby program separately from this skill.
metadata:
  author: mavroth
  version: "0.3.0"
  short-description: Record a stealth browser session as a HAR
---

# Oby

Oby records one browser session as the browser sent it. You get a HAR, every script the engine parsed, and an optional upstream proxy. The browser is CloakBrowser, a patched Chromium that runs on this machine. This skill is version 0.3.0 of https://github.com/mavroth/oby. The installable version is the git tag. The repository README is the long description of every file in the folder.

The script list is the one [Ghostwire](https://github.com/sofianeelhor/ghostwire) records on Chrome, kept next to the traffic. The record is the source of each script the engine parsed. Function hooks, resolved runtime values, and heap search stay in Ghostwire.

## Install this skill

```bash
npx skills add mavroth/oby@v0.3.0 --skill oby
```

`npx skills add mavroth/oby --skill oby` follows the default branch. A later release is the same command with that release's tag.

## Install the program

```bash
git clone https://github.com/mavroth/oby
cd oby
pip install -e .
```

The first start downloads CloakBrowser's Chromium into `~/.cloakbrowser`. No license key is needed.

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

`oby` with no subcommand is `oby browse`. Add `--headless` when no window should appear.

An upstream proxy is `OBY_PROXY`, set in the environment that launches `oby`. Keep a proxy URL that contains a password out of the command line, MCP config, and chat. The browser talks only to the local recorder. Leave the recorder's port alone. No tool can change the proxy after launch.

The server answers in about a second. The first `browser_open` downloads the browser if it is not there yet, so that one call can take minutes.

## While the agent is connected

The project allows every tool on the `oby` server (`.claude/settings.json`). After the folder is trusted once, do not ask the person before each browser tool.

1. Call `browser_open` before any other browser tool. It opens the browser on the recorder, with the profile in the output folder.
2. Go where you were asked with `browser_navigate`. The browser's own startup requests, if any, are written first. The page follows. Every tool that changes the page returns the page afterwards, as a tree with a ref such as `e12` on each element. Use the refs from the latest result with `browser_click`, `browser_type`, `browser_hover`, `browser_select_option`, and `browser_upload_files`. `browser_type` sets any kind of field: text is typed, a date is `YYYY-MM-DD`, a slider is its number, a dropdown takes the option's label, a checkbox takes `true` or `false`. `browser_fill_form` sets several fields in one call. Elements in iframes and shadow DOM have refs too. A dialog is accepted for you and reported in the next result. Call `browser_handle_dialog` first to dismiss it instead. A large page comes back as its controls only, and `browser_snapshot` returns the whole tree.
3. Call `oby_recording` for the folder, `session.har`, `scripts.json`, and the counts. During the visit it counts exchanges so far. A client may prefix the tool name.
4. Close the MCP client. That write produces `session.har` and `scripts.json`. Until then, exchanges are in `flows.jsonl`.

Each launch of `oby browse` or `oby mcp` starts `--out` empty and records this visit. The previous visit moves to `history/<when it began>/`. The profile stays.

## Check the visit

Decide from hosts and counts. Leave cookies, header values, script source, the proxy password, and the egress address in the folder.

A `flows.jsonl` line has `url` and `status`. The page has loaded when the host you asked for is in that file. `scripts.json` has `counts` by kind (`network`, `inline`, `eval`, `function`, `timer`, `blob`) and a `note` that says whether the list came from the engine or from the recording alone. During the visit, `oby_recording` returns `scripts_so_far` and `script_kinds`. `scripts.json` itself appears when the client closes.

`oby_recording` returns paths and counts. It does not return cookies, header values, or script source. `requests_not_recorded` is how many requests the browser got an answer to that the recorder has no exchange for. It should be 0.

To answer a question about the visit while it runs, read the recording through the server. `oby_exchanges` lists exchanges, filters by `host`, `method`, `status`, or `contains`, and gives the script frame that made each request as `initiator`. `oby_exchange` returns one exchange by `index`, with headers and bodies. `oby_messages` returns the WebSocket messages of a handshake exchange. `oby_scripts` lists scripts and finds `contains` in their source. `oby_script` returns a slice of one script by `sha256`. These four return real cookies and tokens. Read what the task needs, and keep those values out of what you tell the person.

`oby_script` also takes `view`: `pretty` reformats the script, and `deobfuscated` also spells out escaped strings, hex numbers, `!![]`, and bracket property names. Nothing is executed, so a rotated string table stays as it is. With `find` it returns the matching lines and their numbers. Search the `deobfuscated` view, where a line is one statement. `oby_scripts` takes `regex`, and lists WebAssembly modules (`kind` `wasm`) with what they import and export.

`oby_fingerprint` lists the fingerprinting APIs the page called, such as canvas, WebGL, audio, navigator, screen, fonts, WebRTC, and storage, with the script, line, and function that called each. It only has data when Oby was started with `--fingerprints`, which runs a script in the page that a site can detect. Add `--fingerprints` to the `args` in the MCP config when the task is to study what a page fingerprints.

`oby_save` writes `session.har`, `scripts.json`, `scripts/`, and `storage.json` now, and the visit keeps recording.

`storage.json` (cookies and localStorage) is written when the browser closes, under `oby browse` and `oby mcp`.

## What was recorded

`session.har` is a HAR 1.2 log. Header order is the header arrays. Each entry's `_oby` object holds the HTTP/2 preface, the mitmcloak result, and every clock reading. Bodies are whole. WebSocket messages are `_webSocketMessages` on the handshake entry, and `ws.jsonl` has them during the visit. A response reaches the page as it arrives. For an event stream, `_oby.events` has each event with the time it came. `_oby.initiator` is the script frame that made the request. Each navigation is a page.

`scripts/` holds each script's source as `<sha256>.js`.

`scripts.json` lists every script the engine parsed: fetched files, inline scripts, `eval`, `new Function`, a string passed to `setTimeout` or `setInterval`, a blob worker, a worker loaded from its own URL, and a script inserted into the page. The listener is a DevTools client on loopback. It turns on Debugger and Network only, skips `debugger` statements, and injects nothing into the page. A string timer is listed as `eval`. An item with `from: wire` took its text from the recorded response, and `reported: false` on it means the file was fetched to run and the engine never named it. What `browser_evaluate` runs is left out.
