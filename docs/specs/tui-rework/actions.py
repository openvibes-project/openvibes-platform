import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, header, menu, page, screen  # noqa: E402

SERVICES = ["ingest", "console", "vulns", "netlog", "distribution"]


def status(sel, popup=None, psel=0):
    body = [header("Status"), "",
            "    {y}▲{/} Certificate for limebox expires in 21 days", "",
            "    {b}Services{/}                                           {d}8 of 8 running{/}"]
    shown = SERVICES[:1] if popup else SERVICES[:3]
    for i, name in enumerate(shown):
        row = f"{name:<15} running   ready    since 18:40"
        if i == sel:
            body.append(f"  {{s}}▸ {{g}}●{{/}}{{s}} {row:<66}{{/}}")
        else:
            body.append(f"    {{g}}●{{/}} {row}")
        if popup and i == sel:
            w = 60
            body.append("        {d}┌─{/} {b}ingest{/} {d}" + "─" * (w - 10) + "┐{/}")
            for j, (act, desc) in enumerate(popup):
                text = f"{act:<10} {desc}"
                if j == psel:
                    body.append(f"        {{d}}│{{/}} {{s}}▸ {text:<{w - 5}}{{/}} {{d}}│{{/}}")
                else:
                    body.append(f"        {{d}}│{{/}}   {text:<{w - 5}} {{d}}│{{/}}")
                if j < len(popup) - 1:
                    body.append("        {d}│" + " " * (w - 1) + "│{/}")
            body.append("        {d}└" + "─" * (w - 1) + "┘{/}")
        elif i < len(shown) - 1:
            body.append("")
    if not popup:
        body.append("    {d}↓ 5 more{/}")
    return body


ACTS = [("Open", "state and log"), ("Restart", "agents reconnect within a minute"),
        ("Stop", "agents keep their findings until it runs")]

shots = [
    ("Status: highlight on ingest", "Nothing to remember: Enter opens the choices.",
     screen("limebox · Status", status(0), bar("{k} Enter {/} Choose"))),
    ("Enter: the choices open under it", "↑↓ inside the choices, Enter to do it, Esc to close them.",
     screen("limebox · Status", status(0, ACTS, 0), bar("{k} Enter {/} Open ingest", "{k} Esc {/} Close  {k} ? {/}"))),
    ("↓ once: Restart", "The bar says what Enter will do.",
     screen("limebox · Status", status(0, ACTS, 1), bar("{k} Enter {/} Restart ingest", "{k} Esc {/} Close  {k} ? {/}"))),
    ("Enter: the question, with arrow buttons", "←→ between Yes and No, Enter to answer. (y and n still work for fast typists.)",
     screen("limebox · Status", status(0), ask("Restart ingest?", "agents reconnect"))),
]
print(page("Actions and questions with the arrows",
           "Your rule applied to Status and to Yes/No questions. Reply per number: yes, or what to change.", shots))
