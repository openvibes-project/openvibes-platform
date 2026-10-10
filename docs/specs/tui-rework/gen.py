"""Renders TUI mockups as 80x24 terminal screens in an HTML fragment.

Markup inside screen lines: {w} white bold, {t} teal, {d} dim, {g} green,
{y} amber, {r} red, {s} selected row, {k} key button, {b} bold; {/} closes.
"""

import html
import re
import sys

W, H = 80, 24

OPEN = [
    "  ___                  ",
    r" / _ \ _ __   ___ _ __  ",
    r"| | | | '_ \ / _ \ '_ \ ",
    r"| |_| | |_) |  __/ | | |",
    r" \___/| .__/ \___|_| |_|",
    r"      |_|               ",
]
VIBES = [
    r"__     _____ ____  _____ ____ ",
    r"\ \   / /_ _| __ )| ____/ ___|",
    " \\ \\ / / | ||  _ \\|  _| \\___ \\",
    r"  \ V /  | || |_) | |___ ___) |",
    r"   \_/  |___|____/|_____|____/",
    "",
]

TAG = re.compile(r"\{(/|[a-z])\}")


def visible(line):
    return len(TAG.sub("", line))


def cells(text):
    return "".join(c if ord(c) < 128 else f'<span class="g1">{c}</span>' for c in html.escape(text))


def render_line(line):
    out, stack = [], 0
    pos = 0
    for m in TAG.finditer(line):
        out.append(cells(line[pos:m.start()]))
        if m.group(1) == "/":
            out.append("</span>")
            stack -= 1
        else:
            out.append(f'<span class="c{m.group(1)}">')
            stack += 1
        pos = m.end()
    out.append(cells(line[pos:]))
    out.append("</span>" * stack)
    pad = W - visible(line)
    if pad < 0:
        sys.exit(f"line too wide ({visible(line)}): {TAG.sub('', line)}")
    return "".join(out) + " " * pad


SHADOW_OPEN = [
    " ██████╗ ██████╗ ███████╗███╗   ██╗",
    "██╔═══██╗██╔══██╗██╔════╝████╗  ██║",
    "██║   ██║██████╔╝█████╗  ██╔██╗ ██║",
    "██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║",
    "╚██████╔╝██║     ███████╗██║ ╚████║",
    " ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝",
]
SHADOW_VIBES = [
    "██╗   ██╗██╗██████╗ ███████╗███████╗",
    "██║   ██║██║██╔══██╗██╔════╝██╔════╝",
    "██║   ██║██║██████╔╝█████╗  ███████╗",
    "╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════██║",
    " ╚████╔╝ ██║██████╔╝███████╗███████║",
    "  ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚══════╝",
]


VERSION = "v0.2.8"
UPDATE = "0.2.9"  # None: up to date


def logo(title):
    # Approved logo A (user, 2026-10-10): OPEN white, VIBES teal. Under it:
    # where you are on the left, the version (and an available update) on
    # the right, on every screen (user, 2026-10-10).
    rows = ["    {w}" + a + "{/}{t}" + b + "{/}" for a, b in zip(SHADOW_OPEN, SHADOW_VIBES)]
    title = title.replace(" · v0.2.8", "")
    right = f"{VERSION}  {{y}}▲ {UPDATE} available{{/}}" if UPDATE else VERSION
    gap = W - 4 - len(title) - visible(right) - 4
    return rows + ["    {d}" + title + "{/}" + " " * gap + "{d}" + right + "{/}"]


def bar(content, right="{k} Esc {/} Back  {k} ? {/}", nav=True):
    # User (2026-10-10): ↑↓ Move first on every screen with a list; not
    # while the bar asks a question.
    inner = W - 4
    body = ("{k} ↑↓ {/} Move  " + content) if nav else content
    gap = inner - visible(body) - visible(right)
    if gap < 1:
        right = ""
        gap = inner - visible(body)
    return [
        "{d}┌" + "─" * (W - 2) + "┐{/}",
        "{d}│{/} " + body + " " * gap + right + " {d}│{/}",
        "{d}└" + "─" * (W - 2) + "┘{/}",
    ]


def screen(title, body, bar_lines):
    # One frame for every screen: one empty line under the logo, then the
    # content, which starts at the logo's left edge (column 4).
    while body and body[0] == "":
        body = body[1:]
    lines = logo(title) + [""] + body
    room = H - len(bar_lines)
    if len(lines) > room:
        sys.exit(f"{title}: {len(lines)} lines, room for {room}")
    lines += [""] * (room - len(lines))
    return "\n".join(render_line(l) for l in lines + bar_lines)


CSS = """
<style>
.term{background:#0d1117;color:#c9d1d9;font:15px/1.13 'Noto Sans Mono','Liberation Mono',monospace;
 padding:14px 16px;border-radius:8px;white-space:pre;display:inline-block;margin:0;
 box-shadow:0 2px 10px rgba(0,0,0,.35)}
.cw{color:#f0f6fc;font-weight:bold}.ct{color:#36b9e0;font-weight:bold}.cd{color:#6e7681}
.cg{color:#3fb950}.cy{color:#d29922}.cr{color:#f85149}.cb{font-weight:bold;color:#f0f6fc}
.cs{background:#1f3a4a;color:#f0f6fc}.ck{background:#30363d;color:#f0f6fc;font-weight:bold}
.g1{display:inline-block;width:1ch;text-align:center;overflow:visible;line-height:1.13}
.shots{display:flex;flex-direction:column;gap:28px;align-items:flex-start}
.shot h3{margin:0 0 6px}.shot p{margin:0 0 8px;max-width:760px}
</style>
"""


def page(heading, subtitle, shots):
    parts = [CSS, f"<h2>{html.escape(heading)}</h2>",
             f'<p class="subtitle">{html.escape(subtitle)}</p>', '<div class="shots">']
    for n, (name, note, text) in enumerate(shots, 1):
        parts.append(f'<div class="shot"><h3>{n}. {html.escape(name)}</h3>'
                     f"<p>{html.escape(note)}</p><pre class=\"term\">{text}</pre></div>")
    parts.append("</div>")
    return "\n".join(parts)


def header(name):
    """Screen header, first content line (rule 12)."""
    return f"    {{t}}━━{{/}} {{b}}{name}{{/}} {{t}}{'━' * (70 - len(name))}{{/}}"


def menu(items, sel, name_w=20):
    """Any list: one empty line between entries (rule 13)."""
    body = []
    for i, (name, desc) in enumerate(items):
        if i == sel:
            body.append(f"  {{s}}▸ {name:<{name_w}} {desc:<{69 - name_w}}{{/}}")
        else:
            body.append(f"    {name:<{name_w}} {{d}}{desc}{{/}}")
        body.append("")
    return body[:-1]
