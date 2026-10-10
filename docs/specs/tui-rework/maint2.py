import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, checkbar, header, menu, page, screen  # noqa: E402


def strip(n):
    return n.replace("{g}", "").replace("{/}", "")


def opt(sel, agent=True, assistant=False, b=None, note=""):
    items = [(("{g}[x]{/}" if agent else "[ ]") + " Agent on this host", "watch this host too"),
             (("{g}[x]{/}" if assistant else "[ ]") + " Assistant", "local AI helper · 2.7 GB download"),
             ("Apply", note or "nothing changed yet")]
    items = [(strip(n) if i == sel else n, v) for i, (n, v) in enumerate(items)]
    helps = {0: "The agent reports this host's own findings and alarms.",
             1: "Answers questions about your findings, on this host, no cloud. Needs 4 GB.",
             2: "Installs or removes what you changed above."}
    body = [header("Optional parts"), ""] + menu(items, sel, 26) + ["", "    {d}" + helps[sel] + "{/}"]
    return screen("limebox · Maintenance › Optional parts", body, b or checkbar())


def ports(sel, rows, b, helptext):
    body = [header("Ports and addresses"), ""] + menu(rows, sel, 22) + ["", "    {d}" + helptext + "{/}"]
    return screen("limebox · Maintenance › Ports and addresses", body, b)


P = [("Console", "8443 · https://limebox.lan:8443"), ("Agent connections", "18423"),
     ("Rule distribution", "18424"), ("Network devices", "514/udp")]
P_EDIT = [("Console", "8443"), ("Agent connections", "18500█"), ("Rule distribution", "18424"),
          ("Network devices", "514/udp")]
P_CHANGED = [("Console", "8443"), ("{y}*{/} Agent connections", "18500 · was 18423"),
             ("Rule distribution", "18424"), ("Network devices", "514/udp"),
             ("Apply", "agents must be told the new port")]

print(page("Maintenance: Optional parts and Ports and addresses",
           "Key by key. Reply per number: yes, or what to change.", [
    ("Maintenance › Optional parts", "What is installed now; Space changes it.", opt(0)),
    ("↓, Space: tick Assistant", "Nothing happens until Apply.",
     opt(1, assistant=True, note="install the assistant")),
    ("↓ to Apply, Enter: the question", "Says what it means.",
     opt(2, assistant=True, note="install the assistant",
         b=ask("Install the assistant?", "2.7 GB"))),
    ("Maintenance › Ports and addresses", "Every port this platform listens on.",
     ports(0, P, bar("{k} Enter {/} Change"), "The console's port; the web address follows it.")),
    ("↓, Enter on Agent connections: type 18500", "Checked as you type: free on this host.",
     ports(1, P_EDIT, bar("{b}Agent connections:{/} type a port  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False),
           "18500 is free on this host.")),
    ("Enter: changed, then ↓ to Apply", "The consequence is said before you apply it.",
     ports(4, P_CHANGED, bar("{k} Enter {/} Apply"),
           "Agents on other hosts need their install line again after this.")),
]))
