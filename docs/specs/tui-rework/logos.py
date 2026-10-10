import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import bar, page, render_line  # noqa: E402

MENU = [
    "",
    "        {g}●{/} All 8 services running   {y}▲{/} Certificate expires in 21 days",
    "",
    "     {s}▸  Status          health, services, logs              {/}",
    "        Settings        {d}how each service works{/}",
    "        Agents          {d}hosts, routers, enrollment{/}",
    "        Maintenance     {d}update, repair, backup, database{/}",
    "        Quit",
]


def home(logo_lines):
    lines = logo_lines + MENU
    bars = bar("{k} ⭡⭣ {/} Choose  {k} Enter {/} Open", "{k} q {/} Quit  {k} ? {/}")
    lines += [""] * (gen.H - len(bars) - len(lines))
    return "\n".join(render_line(l) for l in lines + bars)


def two_tone(open_rows, vibes_rows, indent=2, title=""):
    rows = []
    for i, (a, b) in enumerate(zip(open_rows, vibes_rows)):
        rows.append(" " * indent + "{w}" + a + "{/}{t}" + b + "{/}")
    if title:
        rows.append(" " * indent + "{d}" + title + "{/}")
    return rows


# A. Block letters (figlet "ANSI Shadow"): bold, modern.
shadow_open = [
    " ██████╗ ██████╗ ███████╗███╗   ██╗",
    "██╔═══██╗██╔══██╗██╔════╝████╗  ██║",
    "██║   ██║██████╔╝█████╗  ██╔██╗ ██║",
    "██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║",
    "╚██████╔╝██║     ███████╗██║ ╚████║",
    " ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝",
]
shadow_vibes = [
    "██╗   ██╗██╗██████╗ ███████╗███████╗",
    "██║   ██║██║██╔══██╗██╔════╝██╔════╝",
    "██║   ██║██║██████╔╝█████╗  ███████╗",
    "╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════██║",
    " ╚████╔╝ ██║██████╔╝███████╗███████║",
    "  ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚══════╝",
]
A = two_tone(shadow_open, shadow_vibes, 4) + ["    {d}limebox · v0.2.8{/}"]

# B. Compact half-block letters: three rows, more room for content.
half_open = ["▄▀▀▄ █▀▀▄ █▀▀▀ █▄ █ ", "█  █ █▀▀  █▀▀  █ ▀█ ", " ▀▀  ▀    ▀▀▀▀ ▀  ▀ "]
half_vibes = ["█   █ █ █▀▀▄ █▀▀▀ ▄▀▀▀", " █ █  █ █▀▀▄ █▀▀   ▀▀▄", "  ▀   ▀ ▀▀▀  ▀▀▀▀ ▀▀▀ "]
B = ["", ] + [
    "    {w}" + a + "{/}{t}" + b + "{/}" + ("     {d}limebox · v0.2.8{/}" if i == 1 else "")
    for i, (a, b) in enumerate(zip(half_open, half_vibes))
]

# C. Today's figlet letters, kept but lighter: no shadow row, version beside.
C = gen.logo("limebox · v0.2.8")

# D. A plain wordmark: one line, a small mark, a tagline. Calm, most room.
D = [
    "",
    "   {t}◢◤{/} {w}Open{/}{t}VIBES{/}   {d}security for the network you own{/}",
    "   {d}─────────────────────────────────────────────────────────────────{/}",
    "   {d}limebox · v0.2.8{/}",
]

print(page(
    "A new logo: four directions",
    "Each one on the Home screen, so you can judge it in place. Tell me in the "
    "terminal: A, B, C or D, and anything to change (letters, colours, size, tagline).",
    [
        ("A: Block letters", "Bold and modern, the look of many CLI tools. Six rows tall.", home(A)),
        ("B: Compact half-blocks", "Three rows: still a real logo, leaves more room on every screen.", home(B)),
        ("C: Today's letters", "The current figlet logo, for comparison.", home(C)),
        ("D: Plain wordmark", "One line with a small mark and a tagline. The calmest; the most room.", home(D)),
    ]))
