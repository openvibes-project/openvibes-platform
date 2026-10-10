import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, checkbar, header, menu, page, screen  # noqa: E402

HOME = [("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, ports, certificates, backup"),
        ("System", "network, time, login, restart"), ("Log out", "")]
SYS = [("Network", "192.168.1.50 · DHCP · openvibes-va.lime.lab"),
       ("Time", "in sync · pool.ntp.org · Europe/Stockholm"), ("Login password", "change it for this account"),
       ("SSH", "keys and passwords allowed"), ("Restart", ""), ("Shut down", "")]


def scroll(items, sel, top, shown, w):
    body = [f"    {{d}}⭡ {top} more{{/}}" if top else ""]
    body += menu(items[top:top + shown], sel - top, w)
    rest = len(items) - top - shown
    body.append(f"    {{d}}⭣ {rest} more{{/}}" if rest > 0 else "")
    return body


def home(sel):
    body = ["    {g}●{/} All 8 services running   {y}▲{/} 4 security updates for the OS", ""] + menu(HOME, sel, 15)
    return screen("openvibes-va", body, bar("{k} Enter {/} Open", "{k} ? {/}"))


def system(sel, top=0, b=None):
    return screen("openvibes-va · System", [header("System")] + scroll(SYS, sel, top, 5, 18),
                  b or bar("{k} Enter {/} Open"))


def strip(n):
    return n.replace("{g}", "").replace("{/}", "")


NET = [("(•) DHCP", "address from your network"), ("( ) Fixed address", "you type it"),
       ("{g}[x]{/} DNS from DHCP", "192.168.1.1"), ("Search domain", "lime.lab"),
       ("Host name", "openvibes-va.lime.lab"), ("Apply", "nothing changed")]
NET_OWN = [("(•) DHCP", "address from your network"), ("( ) Fixed address", "you type it"),
           ("[ ] DNS from DHCP", "using your own servers"), ("DNS servers", "192.168.1.10, 192.168.1.11"),
           ("Search domain", "lime.lab"), ("Host name", "openvibes-va.lime.lab"),
           ("Apply", "checked first: both servers answer")]


def net(items, sel, top, b):
    items = [(strip(n) if i == sel else n, v) for i, (n, v) in enumerate(items)]
    return screen("openvibes-va · System › Network", [header("Network: eth0")] + scroll(items, sel, top, 5, 22), b)


print(page("Appliance: Network holds the address, DNS and the host name",
           "Reply per number: yes, or what to change.", [
    ("Appliance Home", "", home(0)),
    ("⭣ twice, Enter: System", "Network, Time, Login password, SSH, Restart, Shut down.", system(0)),
    ("Enter on Network", "How the address is set, first.", net(NET, 0, 0, bar("{k} Space {/} Choose  {k} Enter {/} Confirm"))),
    ("⭣ to DNS from DHCP", "DNS and the host name are on the same screen.", net(NET, 2, 1, checkbar())),
    ("Space: untick it, ⭣ to DNS servers", "Your own servers appear; checked before Apply.",
     net(NET_OWN, 3, 1, bar("{k} Enter {/} Change"))),
    ("⭣ to Host name", "The last thing before Apply.", net(NET_OWN, 5, 2, bar("{k} Enter {/} Change"))),
]))
