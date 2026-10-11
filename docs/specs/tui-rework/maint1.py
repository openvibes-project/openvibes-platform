import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import ask, bar, header, menu, page, pad, screen  # noqa: E402


def entries(items, sel, w=24):
    return menu(items, sel, w)


UPD_INFO = ["    v0.2.8 installed · {y}0.2.9 available{/}",
            "    {d}New: network device alarms · faster docs-only checks · fixes{/}", ""]
UPD = [("{g}[x]{/} Back up first", "~/openvibes-0.2.9-2026-10-10-2041.dump"), ("Update now", "about 3 minutes"),
       ("What's new", "the release notes")]


def update(sel, b, hint=None):
    items = [(n.replace("{g}", "").replace("{/}", "") if i == sel else n, v) for i, (n, v) in enumerate(UPD)]
    tail = ["", hint] if hint else []
    return screen("limebox · Maintenance › Update OpenVIBES",
                  [header("Update OpenVIBES"), ""] + UPD_INFO + entries(items, sel) + tail, b)


USTEPS = ["Back up", "Stop services", "Install packages", "Update the database", "Start services", "Ready"]


def uprog(done, detail, finished=False):
    body = [header("Updating to 0.2.9"), ""]
    for i, s in enumerate(USTEPS):
        if i < done or finished:
            body.append(f"    {{g}}✓{{/}} {s}")
        elif i == done:
            body.append(f"    {{t}}⠹{{/}} {{b}}{s}{{/}}  {{d}}{detail}{{/}}")
        else:
            body.append(f"    {{d}}· {s}{{/}}")
    if finished:
        body += ["", "    {g}✓ Updated to 0.2.9 · everything is ready (2 min 41 s){/}"]
        return screen("limebox · Maintenance › Update OpenVIBES", body, bar("{k} Enter {/} Back to Maintenance", "", nav=False))
    return screen("limebox · Maintenance › Update OpenVIBES", body,
                  bar(f"{{t}}⠹{{/}} Step {done + 1} of {len(USTEPS)}: {USTEPS[done]}", "", nav=False))


CHECKS = [("{g}✓{/} Packages", "all installed"), ("{g}✓{/} Database", "schema 46, reachable"),
          ("{y}▲{/} Certificates", "missing the name 192.168.1.20"),
          ("{y}▲{/} Firewall", "18424/tcp is closed"), ("{g}✓{/} Services", "8 of 8 running")]


def repair(sel, b, fixed=False):
    rows = CHECKS if not fixed else [(n.replace("{y}▲{/}", "{g}✓{/}"), v if "▲" not in n else "fixed")
                                    for n, v in CHECKS]
    body = [header("Repair"), "",
            "    {y}2 problems found{/} · checked just now" if not fixed else "    {g}Everything is in order{/}", ""]
    body += ["    " + pad(n, 18) + " {d}" + v + "{/}" for n, v in rows]
    body += [""]
    acts = [("Fix 2 problems", "certificate and firewall"), ("Check again", "")] if not fixed else [("Check again", "")]
    body += entries(acts, sel)
    return screen("limebox · Maintenance › Repair", body, b)


print(page("Maintenance: Update OpenVIBES and Repair",
           "Key by key. Reply per number: yes, or what to change.", [
    ("Maintenance › Update OpenVIBES", "What you have, what is new; back up is ticked by default.",
     update(1, bar("{k} Enter {/} Update now"))),
    ("Enter on Update now: the question", "Says what will happen.",
     update(1, ask("Update to 0.2.9?", "about 3 min"))),
    ("Updating", "Every step and what it is doing now.", uprog(2, "12 of 17 packages")),
    ("Done", "One clear result line.", uprog(0, "", finished=True)),
    ("Maintenance › Repair", "It checks first and lists what it found; nothing changes yet.",
     repair(0, bar("{k} Enter {/} Fix 2 problems"))),
    ("Enter on Fix 2 problems", "Fixed; the list shows it.", repair(0, bar("{g}✓{/} 2 problems fixed (12 s)"), fixed=True)),
]))
