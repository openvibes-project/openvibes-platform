import sys

sys.path.insert(0, sys.argv[1])
from gen import bar, header, menu, page, screen  # noqa: E402

HOME = [("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, ports, certificates, backup"), ("Quit", "")]
MAINT = [("Update OpenVIBES", "0.2.9 is available"),
         ("Operating system", "AlmaLinux 9.6 · 23 updates, 4 for security"),
         ("Repair", "check every step, fix what is wrong"),
         ("Optional parts", "agent on this host · assistant"),
         ("Ports and addresses", "console 8443, agents 18423 and 18424, devices 514"),
         ("Certificates", "signed by Lime Lab Root CA · expires in 21 days"),
         ("Database", "schema 46 · 3.1 GB · clean up old data"),
         ("Console sign-in", "reset the admin password"),
         ("Back up", "save the database to a file"),
         ("Uninstall", "remove OpenVIBES from this host")]


def home(sel):
    body = ["    {g}●{/} All 8 services running   {y}▲{/} Certificate expires in 21 days", ""] + menu(HOME, sel, 15)
    return screen("limebox", body, bar("{k} Enter {/} Open", "{k} q {/} Quit  {k} ? {/}"))


def maint(sel, top):
    shown = 5
    body = [header("Maintenance"), f"    {{d}}↑ {top} more{{/}}" if top else ""]
    body += menu(MAINT[top:top + shown], sel - top)
    rest = len(MAINT) - top - shown
    body.append(f"    {{d}}↓ {rest} more{{/}}" if rest > 0 else "")
    return screen("limebox · Maintenance", body, bar("{k} Enter {/} Open"))


print(page("Home without Agents, and the whole Maintenance list",
           "Agents are handled in the console; the TUI only asks about the agent on this host at install. "
           "Reply per number: yes, or what to change.", [
    ("Home", "Status, Maintenance, Quit.", home(0)),
    ("↓, Enter: Maintenance", "The first five of ten.", maint(0, 0)),
    ("↓ through the list", "Scrolled to the middle: Optional parts highlighted.", maint(3, 2)),
    ("↓ to the end", "Uninstall last.", maint(9, 5)),
]))
