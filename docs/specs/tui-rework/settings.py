import sys

sys.path.insert(0, sys.argv[1])
from gen import bar, page, screen  # noqa: E402


def header(name):
    rule = "━" * (70 - len(name))
    return f"    {{t}}━━{{/}} {{b}}{name}{{/}} {{t}}{rule}{{/}}"


SERVICES = [
    ("Console", "web address, sign-in, assistant"),
    ("Agent connections", "limits, timeouts, how long kept"),
    ("Rule distribution", "limits, timeouts"),
    ("Vulnerabilities", "feeds, proxy, how often to check"),
    ("Network devices", "port, how alarms are grouped"),
    ("Admin", "database connection"),
]


def menu(items, sel):
    """A menu (choices of where to go): one blank line between entries."""
    body = []
    for i, (name, desc) in enumerate(items):
        if i == sel:
            body.append(f"  {{s}}▸ {name:<20} {desc:<49}{{/}}")
        else:
            body.append(f"    {name:<20} {{d}}{desc}{{/}}")
        body.append("")
    return body[:-1]


def settings(sel):
    return [header("Settings"), ""] + menu(SERVICES, sel)


VULNS = [
    ("Feeds", None),
    ("How often to check", "every 60 minutes"),
    ("Fedora mirror list", "mirrors.fedoraproject.org/…"),
    ("Proxy", "none"),
    ("NVD API key", "not set (slower lookups)"),
    ("Enrichment", None),
    ("Known exploited (CISA)", "on"),
    ("Exploit likelihood (EPSS)", "on"),
]
HELP = {
    "How often to check": "How often the feeds are checked for new advisories (15 to 1440 minutes).",
    "Proxy": "Proxy for feed downloads, e.g. http://proxy.example:3128. Empty: direct.",
}


def vulns(sel, value=None, changed=False, editing=False):
    body = [header("Settings: Vulnerabilities"), ""]
    for name, val in VULNS:
        if val is None:
            body.append(f"    {{b}}{name}{{/}}")
            continue
        shown = value if (name == "Proxy" and value) else val
        mark = "{y}*{/}" if (changed and name == "Proxy") else " "
        cursor = "█" if (editing and name == "Proxy") else ""
        if name == sel:
            body.append(f"  {{s}}▸ {{/}}{mark}{{s}} {name:<26} {shown + cursor:<40}{{/}}")
        else:
            body.append(f"    {mark} {name:<26} {{d}}{shown}{{/}}")
    body.append("")
    if changed:
        body.append("    {y}1 unsaved change:{/} Proxy  none → http://proxy.lan:3128")
    else:
        body.append("    {d}" + HELP.get(sel, "") + "{/}")
    return body


shots = [
    ("Settings", "One line per service, in plain words. Enter opens it.",
     screen("limebox · Settings", settings(3), bar("{k} Enter {/} Open"))),
    ("Settings: Vulnerabilities", "The service's settings, grouped, with plain names. "
     "The line under the list explains the highlighted setting.",
     screen("limebox · Settings › Vulnerabilities", vulns("Proxy"), bar("{k} Enter {/} Change"))),
    ("Changing a value", "Enter: you type the new value in place. ↑↓ Move is gone while you type.",
     screen("limebox · Settings › Vulnerabilities", vulns("Proxy", "http://proxy.lan:3128", editing=True),
            bar("{b}Proxy:{/} type the new value  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False))),
    ("After the change", "* marks what changed; the bar offers to save and restart the service in one step.",
     screen("limebox · Settings › Vulnerabilities", vulns("Proxy", "http://proxy.lan:3128", changed=True),
            bar("{k} w {/} Save and restart vulns  {k} u {/} Undo"))),
    ("Saving", "The bar shows progress and the result, as with Restart.",
     screen("limebox · Settings › Vulnerabilities", vulns("Proxy", "http://proxy.lan:3128"),
            bar("{g}✓{/} Saved · vulns restarted and ready (3 s)"))),
]

print(page("Settings, with everything agreed so far",
           "Reply in the terminal per number: yes, or what to change.", shots))


MENU = [("Status", "health, services, logs"), ("Settings", "how each service works"),
        ("Agents", "hosts, routers, enrollment"), ("Maintenance", "update, repair, backup, database"),
        ("Quit", "")]


def home(sel):
    body = ["    {g}●{/} All 8 services running   {y}▲{/} Certificate expires in 21 days", ""] + menu(MENU, sel)
    return screen("limebox · v0.2.8", body, bar("{k} Enter {/} Open", "{k} q {/} Quit  {k} ? {/}"))


def vulns_at(sel_name):
    return screen("limebox · Settings › Vulnerabilities", vulns(sel_name), bar("{k} Enter {/} Change"))


flow = [
    ("Start: Home", "You open the TUI. The highlight is on Status.", home(0)),
    ("Press ↓", "The highlight moves to Settings.", home(1)),
    ("Press Enter", "Settings opens, highlight on the first service.",
     screen("limebox · Settings", settings(0), bar("{k} Enter {/} Open"))),
    ("Press ↓ three times", "Agent connections, Rule distribution, then Vulnerabilities.",
     screen("limebox · Settings", settings(3), bar("{k} Enter {/} Open"))),
    ("Press Enter", "Vulnerabilities opens, highlight on its first setting.", vulns_at("How often to check")),
    ("Press ↓ twice", "Past the Fedora mirror list, to Proxy. The line below explains it.", vulns_at("Proxy")),
    ("Press Enter", "You type the new value in place.",
     screen("limebox · Settings › Vulnerabilities", vulns("Proxy", "http://proxy.lan:3128", editing=True),
            bar("{b}Proxy:{/} type the new value  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False))),
    ("Type the address, press Enter", "The change is marked *, not saved yet.",
     screen("limebox · Settings › Vulnerabilities", vulns("Proxy", "http://proxy.lan:3128", changed=True),
            bar("{k} w {/} Save and restart vulns  {k} u {/} Undo"))),
    ("Press w", "Saved and restarted; Esc twice takes you back to Home.",
     screen("limebox · Settings › Vulnerabilities", vulns("Proxy", "http://proxy.lan:3128"),
            bar("{g}✓{/} Saved · vulns restarted and ready (3 s)"))),
]
print("<!--split-->")
print(page("Changing a setting, key by key",
           "From Home to a saved proxy setting: 9 screens, each titled with the key you pressed. "
           "Reply per number: yes, or what to change.", flow))
