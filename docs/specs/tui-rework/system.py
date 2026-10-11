import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import ask, bar, header, menu, page, pad, screen  # noqa: E402

HOME = [("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, ports, certificates, backup"),
        ("System", "network, name, time, restart"), ("Log out", "")]


def home(sel):
    body = ["    {g}●{/} All 8 services running   {y}▲{/} 4 security updates for the OS", ""] + menu(HOME, sel, 15)
    return screen("openvibes-va", body, bar("{k} Enter {/} Open", "{k} ? {/}"))


SYS = [("Network", "192.168.1.50 · DHCP · eth0"), ("DNS", "192.168.1.1 · from DHCP · lime.lab"),
       ("Host name", "openvibes-va.lime.lab"),
       ("Time", "in sync · pool.ntp.org · Europe/Stockholm"), ("Login password", "change it for this account"),
       ("SSH", "keys and passwords allowed"), ("Restart", ""), ("Shut down", "")]


def system(sel, top=0, b=None):
    shown = 5
    body = [header("System"), f"    {{d}}⭡ {top} more{{/}}" if top else ""]
    body += menu(SYS[top:top + shown], sel - top, 18)
    rest = len(SYS) - top - shown
    body.append(f"    {{d}}⭣ {rest} more{{/}}" if rest > 0 else "")
    return screen("openvibes-va · System", body, b or bar("{k} Enter {/} Open"))


def radio(i, chosen, name):
    return ("(•) " if i == chosen else "( ) ") + name


def net(sel, static=False, b=None):
    rows = [(radio(0, 1 if static else 0, "DHCP"), "address from your network"),
            (radio(1, 1 if static else 0, "Fixed address"), "you type it below")]
    if static:
        rows += [("Address", "192.168.1.50/24"), ("Gateway", "192.168.1.1"), ("DNS", "192.168.1.1, 9.9.9.9"),
                 ("Apply", "agents keep working if the address stays the same")]
    else:
        rows += [("Apply", "nothing changed")]
    body = [header("Network: eth0"), "", "    {d}Now: 192.168.1.50/24 · gateway 192.168.1.1 · DNS 192.168.1.1{/}", ""]
    body += menu(rows[:5] if static else rows, sel, 20)
    if static:
        body = [header("Network: eth0"), "    {d}⭡ 1 more{/}"] + menu(rows[1:5], sel - 1, 20) + ["    {d}⭣ 1 more{/}"]
    return screen("openvibes-va · System › Network", body, b or bar("{k} Space {/} Choose  {k} Enter {/} Confirm"))


def dns(sel, own=False, b=None):
    rows = [(("{g}[x]{/}" if not own else "[ ]") + " Use the DNS from DHCP", "192.168.1.1")]
    if own:
        rows += [("Servers", "192.168.1.10, 192.168.1.11"), ("Search domain", "lime.lab"),
                 ("Apply", "checked first: both servers answer")]
    else:
        rows += [("Search domain", "lime.lab"), ("Apply", "nothing changed")]
    rows = [(n.replace("{g}", "").replace("{/}", "") if i == sel else n, v) for i, (n, v) in enumerate(rows)]
    body = [header("DNS"), "", "    {d}Name servers this appliance asks; agents and feeds need them.{/}", ""]
    body += menu(rows, sel, 26)
    return screen("openvibes-va · System › DNS", body, b or bar("{k} Space {/} Select/deselect  {k} Enter {/} Confirm"))


print(page("Appliance only: Home with System, and the System screens",
           "On the appliance you SSH in and land here; Quit becomes Log out. Reply per number: yes, or what to change.", [
    ("Appliance Home", "System is added; Log out ends the SSH session.", home(0)),
    ("⭣ twice, Enter: System", "Everything a sealed appliance needs.", system(0)),
    ("Enter on Network", "DHCP now; the current address on top.", net(0)),
    ("⭣, Space: Fixed address", "The address fields appear, filled with what DHCP gave.", net(2, static=True,
                                                                                            b=bar("{k} Enter {/} Change"))),
    ("From System, ⭣, Enter: DNS", "From DHCP now.", dns(0)),
    ("Space: untick, then ⭣ to Servers", "Your own servers; checked before Apply.",
     dns(1, own=True, b=bar("{k} Enter {/} Change"))),
    ("⭣ through System to Restart", "Restart and Shut down last.", system(6, top=3, b=bar("{k} Enter {/} Restart"))),
    ("Enter on Restart", "The usual question.", system(6, top=3, b=ask("Restart the appliance?", "about 1 minute"))),
]))
