import sys

sys.path.insert(0, sys.argv[1])
from gen import bar, header, menu, page, screen  # noqa: E402

HOME = [("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, ports, certificates, backup"), ("Quit", "")]


def home(up, lr):
    body = ["    {g}●{/} All 8 services running   {y}▲{/} Certificate expires in 21 days", ""] + menu(HOME, 0, 15)
    body += ["", f"    {{d}}In a question:{{/}} {{k}} {lr} {{/}} Yes or No"]
    b = bar("{k} Enter {/} Open", "{k} q {/} Quit  {k} ? {/}")
    b[1] = b[1].replace("{k} ⭡⭣ {/}", "{k} " + up + " {/}")
    # keep the bar the same width when the label is longer
    return screen("limebox", body, bar(f"{{k}} Enter {{/}} Open", "{k} q {/} Quit  {k} ? {/}", nav=False)[:1]
                  + ["{d}│{/} " + f"{{k}} {up} {{/}} Move  {{k}} Enter {{/}} Open"
                     + " " * (76 - len(f" {up}  Move   Enter  Open") - len(" q  Quit   ? ")) + "{k} q {/} Quit  {k} ? {/} {d}│{/}"]
                  + bar("", nav=False)[2:])


print(page("Arrow keys: three ways to draw them",
           "Pick the one that looks right; also try the printf line in your own terminal.", [
    ("A: thin arrows ↑↓ ←→", "Today's choice.", home("↑↓", "←→")),
    ("B: triangles ▲▼ ◀▶", "Bolder; usually letter-sized.", home("▲▼", "◀▶")),
    ("C: words", "Always the right size; wider.", home("Up/Down", "Left/Right")),
]))
