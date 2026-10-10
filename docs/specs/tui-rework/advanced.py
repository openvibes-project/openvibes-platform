import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import bar, header, pad, page, screen  # noqa: E402

gen.UPDATE = None
STEPS = ["Optional", "Names", "Certificates", "Ports", "Review"]


def steps_line(n):
    parts = []
    for i, s in enumerate(STEPS):
        if i < n:
            parts.append("{g}✓{/} {d}" + s + "{/}")
        elif i == n:
            parts.append("{t}●{/} {b}" + s + "{/}")
        else:
            parts.append("{d}○ " + s + "{/}")
    return "    " + "  ".join(parts)


def rows(items, sel, top=0, shown=5, w=22):
    body = [f"    {{d}}↑ {top} more{{/}}" if top else ""]
    out = []
    for i, (name, val) in enumerate(items[top:top + shown], top):
        if i == sel:
            out.append(f"  {{s}}▸ {pad(name, w)} {pad(val, 69 - w)}{{/}}")
        else:
            out.append(f"    {pad(name, w)} {{d}}{val}{{/}}")
        out.append("")
    body += out[:-1]
    rest = len(items) - top - shown
    body.append(f"    {{d}}↓ {rest} more{{/}}" if rest > 0 else "")
    return body


def step(n, items, sel, help_text, bar_lines, top=0, shown=4, w=22):
    body = [steps_line(n)] + rows(items, sel, top, shown, w) + ["    {d}" + help_text + "{/}"]
    return screen(f"limebox · Install › {STEPS[n]}", body, bar_lines)


# User: the core (console, agent connections, vulnerabilities, rule
# distribution, own-rule signing, baseline rules) is always installed and
# not offered as a choice; only the genuinely optional parts are.
COMP = [("{g}[x]{/} Agent on this host", "watch this host too"),
        ("[ ] Assistant", "local AI helper · 2.7 GB download"),
        ("Next", "names")]


def comp(sel, top=0):
    items = [(n.replace("{g}", "").replace("{/}", "") if i == sel else n, v) for i, (n, v) in enumerate(COMP)]
    helps = {0: "Untick only if this server must not run an agent.",
             1: "Answers questions about your findings, on this host, no cloud. Needs 4 GB.",
             2: "Go on to the names this host is reached by."}
    b = bar("{k} Enter {/} Next") if sel == 2 else bar("{k} Space {/} Select")
    return step(0, items, sel, helps.get(sel, ""), b, top, 4, 26)


NAMES = [("Host name", "limebox.lan"), ("Other names", "192.168.1.10"), ("Next", "certificates")]
CERTS = [("(•) Quick", "the root key is written once to a file you move offline"),
         ("( ) Careful", "the root key never touches this host; you sign elsewhere"),
         ("Root key file", "~/openvibes-root-ca.key"), ("Next", "ports")]
PORTS = [("Console", "443 · https"), ("Agent connections", "18423"), ("Rule distribution", "18424"),
         ("Network devices", "514/udp · you open it in your firewall"), ("Next", "review")]
REVIEW = [("Optional", "agent on this host · no assistant"), ("Names", "limebox.lan, 192.168.1.10"),
          ("Certificates", "quick · ~/openvibes-root-ca.key"), ("Ports", "443, 18423, 18424, 514/udp"),
          ("Install", "asks for your password once")]

if __name__ == "__main__":
    print(page("Choose what to install: five short steps",
               "The steps line shows where you are; Enter on Next moves on, Esc goes back a step. "
               "Reply per number: yes, or what to change.", [
        ("Step 1: Optional", "Only the optional parts; the rest of OpenVIBES is always installed.", comp(0)),
        ("↓ to Assistant", "Off by default: a large download.", comp(1)),
        ("Step 2: Names", "Enter edits in place.",
         step(1, NAMES, 0, "The name agents and your browser use to reach this host.", bar("{k} Enter {/} Change"))),
        ("Step 3: Certificates", "Space picks one of the two.",
         step(2, CERTS, 0, "Fine for most: keep the file safe and offline after the install.",
              bar("{k} Space {/} Choose"), w=16)),
        ("Step 4: Ports", "Taken ports are flagged here, before anything is installed.",
         step(3, PORTS, 0, "The web address port. 443 is free on this host.", bar("{k} Enter {/} Change"))),
        ("Step 5: Review", "Every choice on one screen; Enter on a line jumps back to that step.",
         step(4, REVIEW, 4, "Starts the install; it asks for your password once.", bar("{k} Enter {/} Install"))),
    ]))
