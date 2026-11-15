"""Make a recorded script readable, without running it.

Two views of a script, both written next to the original and never in its
place:

pretty        the same code, reformatted, one statement to a line.
deobfuscated  the pretty view after the rewrites below, which undo the
              cheap tricks an obfuscator plays on the text.

The rewrites change how the code is spelled and not what it does:

- `'\\x68\\x69'` and `'\\u0068i'` become `'hi'`
- `0x1f` becomes `31`
- `!![]`, `![]`, `!0`, `!1`, and `void 0` become `true`, `false`, `true`,
  `false`, and `undefined`
- `obj['name']` becomes `obj.name`
- `'ab' + 'cd'` becomes `'abcd'`
- `names[3]` becomes the string it stands for, when `names` is a list of
  strings that the script only ever reads by a fixed index

Nothing here executes the script, so what needs execution is left alone: a
string table that is rotated and looked up through a decoder function, and
flattened control flow. When the `webcrack` program is installed it is used
instead, since it handles those. It is never downloaded from here.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

VIEWS = ("source", "pretty", "deobfuscated")
_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*\Z")
_HEX = re.compile(r"(?<![A-Za-z0-9_$.])0[xX]([0-9a-fA-F]+)(?![A-Za-z0-9_$])")
_WORDS = (
    (re.compile(r"!!\[\]"), "true"),
    (re.compile(r"!\[\]"), "false"),
    (re.compile(r"(?<![A-Za-z0-9_$)\]!])!0(?![A-Za-z0-9_$.])"), "true"),
    (re.compile(r"(?<![A-Za-z0-9_$)\]!])!1(?![A-Za-z0-9_$.])"), "false"),
    (re.compile(r"(?<![A-Za-z0-9_$.])void 0(?![A-Za-z0-9_$.])"), "undefined"),
)
_ESCAPE = re.compile(r"\\(?:x([0-9a-fA-F]{2})|u([0-9a-fA-F]{4})|u\{([0-9a-fA-F]{1,6})\})")
# A `/` after one of these starts a regular expression, not a division.
_BEFORE_REGEX = set("(,=:[!&|?{};+-*%<>~^")
_REGEX_WORDS = ("return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "do")
_RESERVED = frozenset(
    "break case catch class const continue debugger default delete do else export extends finally for function if "
    "import in instanceof new return super switch this throw try typeof var void while with yield let static "
    "enum await implements package protected interface private public null true false".split()
)
# What may come before a string for `'a' + 'b'` to be safe to join.
_SAFE_BEFORE = set("(,=[{:;?+!&|")


def tokens(source: str) -> list[tuple[str, str]]:
    """Split a script into code, strings, templates, comments, and regular expressions."""
    out: list[tuple[str, str]] = []
    code: list[str] = []
    at, size = 0, len(source)

    def flush() -> None:
        if code:
            out.append(("code", "".join(code)))
            code.clear()

    def last_significant() -> str:
        for piece in reversed(code):
            stripped = piece.rstrip()
            if stripped:
                return stripped
        for kind, text in reversed(out):
            if kind == "comment":
                continue
            return text.rstrip() if kind == "code" else "x"
        return ""

    while at < size:
        char = source[at]
        nxt = source[at + 1] if at + 1 < size else ""
        if char in "'\"":
            end = at + 1
            while end < size and source[end] != char:
                if source[end] == "\n":
                    break
                end += 2 if source[end] == "\\" else 1
            end = min(end + 1, size)
            flush()
            out.append(("string", source[at:end]))
            at = end
        elif char == "`":
            end, depth = at + 1, 0
            while end < size:
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == "$" and source[end + 1 : end + 2] == "{":
                    depth += 1
                    end += 2
                    continue
                if depth and source[end] == "}":
                    depth -= 1
                elif not depth and source[end] == "`":
                    break
                end += 1
            end = min(end + 1, size)
            flush()
            out.append(("template", source[at:end]))
            at = end
        elif char == "/" and nxt == "/":
            end = source.find("\n", at)
            end = size if end == -1 else end
            flush()
            out.append(("comment", source[at:end]))
            at = end
        elif char == "/" and nxt == "*":
            end = source.find("*/", at + 2)
            end = size if end == -1 else end + 2
            flush()
            out.append(("comment", source[at:end]))
            at = end
        elif char == "/":
            before = last_significant()
            starts = not before or before[-1] in _BEFORE_REGEX or before.endswith(_REGEX_WORDS)
            end, in_class, closed = at + 1, False, False
            while starts and end < size and source[end] != "\n":
                if source[end] == "\\":
                    end += 2
                    continue
                if source[end] == "[":
                    in_class = True
                elif source[end] == "]":
                    in_class = False
                elif source[end] == "/" and not in_class:
                    closed = True
                    break
                end += 1
            if closed:
                end += 1
                while end < size and source[end].isalpha():
                    end += 1
                flush()
                out.append(("regex", source[at:end]))
                at = end
            else:
                code.append(char)
                at += 1
        else:
            code.append(char)
            at += 1
    flush()
    return out


def _readable(literal: str) -> str:
    """Turn \\xHH and \\uHHHH into the characters they stand for, where that is printable."""
    quote = literal[0]

    def swap(match: re.Match) -> str:
        char = chr(int(match.group(1) or match.group(2) or match.group(3), 16))
        if char in (quote, "\\") or not char.isprintable() or 0xD800 <= ord(char) <= 0xDFFF:
            return match.group(0)
        return char

    # An escaped backslash is not the start of an escape.
    parts = literal.split("\\\\")
    return "\\\\".join(_ESCAPE.sub(swap, part) for part in parts)


def _body(literal: str) -> str:
    return literal[1:-1]


def rewrite(source: str) -> tuple[str, dict]:
    """Apply the spelling rewrites. Returns the new text and how many of each were made."""
    made = {"strings": 0, "numbers": 0, "words": 0, "lookups": 0, "properties": 0, "joins": 0}
    parts = [list(pair) for pair in tokens(source)]
    for part in parts:
        if part[0] == "string" and len(part[1]) >= 2 and part[1][-1] == part[1][0]:
            plain = _readable(part[1])
            if plain != part[1]:
                made["strings"] += 1
                part[1] = plain
        elif part[0] == "code":
            text, count = _HEX.subn(lambda match: str(int(match.group(1), 16)), part[1])
            made["numbers"] += count
            for pattern, word in _WORDS:
                text, count = pattern.subn(word, text)
                made["words"] += count
            part[1] = text
    made["lookups"] = _inline_tables(parts)
    # 'ab' + 'cd' -> 'abcd', left to right, so a chain folds into one.
    index = 0
    while index + 2 < len(parts):
        first, between, second = parts[index], parts[index + 1], parts[index + 2]
        after = parts[index + 3][1].lstrip()[:1] if index + 3 < len(parts) else ""
        before = parts[index - 1][1].rstrip()[-1:] if index and parts[index - 1][0] == "code" else ""
        if (
            first[0] == second[0] == "string"
            and between[0] == "code"
            and between[1].strip() == "+"
            and first[1][0] == second[1][0]
            and first[1][-1] == first[1][0]
            and second[1][-1] == second[1][0]
            and after not in (".", "[", "(")
            and (not index or before in _SAFE_BEFORE or before == "")
        ):
            first[1] = first[1][:-1] + second[1][1:]
            del parts[index + 1 : index + 3]
            made["joins"] += 1
            continue
        index += 1
    # obj['name'] -> obj.name
    index = 1
    while index + 1 < len(parts):
        left, middle, right = parts[index - 1], parts[index], parts[index + 1]
        name = _body(middle[1]) if middle[0] == "string" else ""
        opener = left[1].rstrip()
        if (
            left[0] == "code"
            and right[0] == "code"
            and opener.endswith("[")
            and right[1].lstrip().startswith("]")
            and _IDENT.match(name)
            and name not in _RESERVED
            and len(opener) > 1
            and (opener[-2].isalnum() or opener[-2] in "_$)]")
        ):
            left[1] = opener[:-1] + "." + name
            right[1] = right[1].lstrip()[1:]
            del parts[index]
            made["properties"] += 1
            continue
        index += 1
    return "".join(part[1] for part in parts), made


_TABLE = re.compile(r"(?:^|[;{}\s])(?:var|let|const)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*\[\s*\Z")


def _inline_tables(parts: list[list[str]]) -> int:
    """Replace `names[3]` with its string, for each list of strings only read by a fixed index.

    A list that is handed to a function, measured, or written to may be
    reordered while the script runs, and then the index means something
    else. Those are left alone, which is every table a real obfuscator
    rotates. The declaration is kept, so the script still means the same.
    """
    made = 0
    index = 0
    while index < len(parts):
        found = _TABLE.search(parts[index][1]) if parts[index][0] == "code" else None
        if not found:
            index += 1
            continue
        name = found.group(1)
        values: list[str] = []
        at = index + 1
        while at + 1 < len(parts) and parts[at][0] == "string" and parts[at + 1][0] == "code":
            values.append(parts[at][1])
            if parts[at + 1][1].strip() != ",":
                break
            at += 2
        closes = at + 1 < len(parts) and parts[at + 1][1].lstrip().startswith("]")
        index += 1
        if not values or not closes:
            continue
        use = re.compile(r"(?<![A-Za-z0-9_$.])" + re.escape(name) + r"(?![A-Za-z0-9_$])")
        read = re.compile(use.pattern + r"\[(\d+)\](?!\s*(?:=(?!=)|\+\+|--|[-+*/%&|^]=))")
        uses = reads = 0
        for kind, text in parts:
            if kind == "code":
                uses += len(use.findall(text))
                reads += sum(1 for match in read.finditer(text) if int(match.group(1)) < len(values))
            elif kind == "template" and use.search(text):
                uses += 2
        # One use is the declaration itself.
        if not reads or uses != reads + 1:
            continue
        rebuilt: list[list[str]] = []
        for kind, text in parts:
            if kind != "code":
                rebuilt.append([kind, text])
                continue
            last = 0
            for match in read.finditer(text):
                rebuilt.append(["code", text[last : match.start()]])
                rebuilt.append(["string", values[int(match.group(1))]])
                last = match.end()
                made += 1
            rebuilt.append(["code", text[last:]])
        parts[:] = [part for part in rebuilt if part[1] != "" or part[0] != "code"]
    return made


def pretty(source: str) -> str:
    """The same code, reformatted."""
    import jsbeautifier

    class Formatter(jsbeautifier.Beautifier):
        # The library's own "unpackers" guess at obfuscators and can drop a
        # declaration the rest of the script still reads. Formatting only.
        def unpack(self, source, evalcode=False):
            return source

    options = jsbeautifier.default_options()
    options.indent_size = 2
    options.preserve_newlines = False
    options.wrap_line_length = 0
    return Formatter().beautify(source, options)


def _webcrack(source: str) -> str | None:
    program = shutil.which("webcrack")
    if not program:
        return None
    try:
        done = subprocess.run([program], input=source, capture_output=True, text=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = done.stdout.strip()
    return text if done.returncode == 0 and text else None


def deobfuscate(source: str) -> tuple[str, dict]:
    """The readable form of a script, and what produced it."""
    cracked = _webcrack(source)
    if cracked is not None:
        return cracked + "\n", {"tool": "webcrack"}
    text, made = rewrite(source)
    return pretty(text) + "\n", {"tool": "oby", "rewrites": made}


def view(folder: Path, sha256: str, source: str, which: str) -> tuple[str, dict]:
    """One view of a script, made once and kept in `folder` next to the original."""
    if which not in VIEWS:
        raise ValueError(f"view is one of {', '.join(VIEWS)}")
    if which == "source":
        return source, {}
    suffix = "pretty" if which == "pretty" else "deob"
    path = Path(folder) / f"{sha256}.{suffix}.js"
    if path.is_file():
        return path.read_text(encoding="utf-8", errors="surrogatepass"), {"file": f"{Path(folder).name}/{path.name}"}
    if which == "pretty":
        text, how = pretty(source) + "\n", {}
    else:
        text, how = deobfuscate(source)
    try:
        Path(folder).mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", errors="surrogatepass")
        how["file"] = f"{Path(folder).name}/{path.name}"
    except OSError:
        pass
    return text, how
