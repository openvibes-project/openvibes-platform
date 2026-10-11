import sys

sys.path.insert(0, sys.argv[1])
from gen import bar, header, menu, page, screen  # noqa: E402

HOME = [("Status", "health, services, logs"), ("Agents", "hosts, routers, enrollment"),
        ("Maintenance", "update, repair, ports, certificates, database"), ("Quit", "")]
MAINT = [("Update", "0.2.9 is available"), ("Repair", "check every step, fix what is wrong"),
         ("Ports and addresses", "console 443, agents 18423 and 18424, devices 514"),
         ("Certificates", "expires in 21 days · other names"),
         ("Database", "schema 46 · 3.1 GB · clean up old data"),
         ("Console sign-in", "reset the admin password"),
         ("Back up", "save the database to a file"),
         ("Uninstall", "remove OpenVIBES from this host")]
AGENTS = [("Agents", "12 online · 1 not seen for 2 hours"),
          ("Add a host", "the install line for a new agent"),
          ("Network devices", "routers and firewalls that send events"),
          ("Enrollment tokens", "1 active")]


def home(sel):
    body = ["    {g}●{/} All 8 services running   {y}▲{/} Certificate expires in 21 days", ""] + menu(HOME, sel, 15)
    return screen("limebox · v0.2.8", body, bar("{k} Enter {/} Open", "{k} q {/} Quit  {k} ? {/}"))


def maint(sel, top=0, shown=5):
    rows = MAINT[top:top + shown]
    # The scroll hints sit inside the one-line gaps, so every gap stays one line.
    body = [header("Maintenance")]
    body += [f"    {{d}}↑ {top} more{{/}}" if top else ""]
    body += menu(rows, sel - top)
    rest = len(MAINT) - top - shown
    body += [f"    {{d}}↓ {rest} more{{/}}" if rest > 0 else ""]
    return screen("limebox · Maintenance", body, bar("{k} Enter {/} Open"))


def agents(sel):
    body = [header("Agents"), ""] + menu(AGENTS, sel)
    return screen("limebox · Agents", body, bar("{k} Enter {/} Open"))


print(page("Home, Maintenance and Agents",
           "Settings is gone from Home: what stays in the TUI lives under Maintenance; the rest moves to the "
           "console. Every list has an empty line between entries. Reply per number: yes, or what to change.",
           [
               ("Home", "Four entries.", home(0)),
               ("Press ↓ twice, then Enter: Maintenance", "Highlight on Update. Three more entries below.", maint(0)),
               ("↓ to the bottom: the list scrolls", "Back up and Uninstall come into view; the counts follow.", maint(7, 3)),
               ("From Home: ↓ once, Enter: Agents", "Agents, adding a host, network devices, tokens.", agents(0)),
           ]))
