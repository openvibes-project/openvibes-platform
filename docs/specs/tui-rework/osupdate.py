import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, header, menu, page, screen  # noqa: E402

MAINT = [("Update OpenVIBES", "0.2.9 is available"),
         ("Operating system", "AlmaLinux 9.6 · 23 updates, 4 for security"),
         ("Repair", "check every step, fix what is wrong"),
         ("Ports and addresses", "console 443, agents 18423 and 18424, devices 514"),
         ("Certificates", "expires in 21 days · other names"),
         ("Database", "schema 46 · 3.1 GB · clean up old data"),
         ("Console sign-in", "reset the admin password"),
         ("Back up", "save the database to a file"),
         ("Uninstall", "remove OpenVIBES from this host")]


def maint(sel):
    body = [header("Maintenance"), ""] + menu(MAINT[:5], sel) + ["    {d}↓ 4 more{/}"]
    return screen("limebox · Maintenance", body, bar("{k} Enter {/} Open"))


def os_screen(bar_lines, state="available"):
    body = [header("Operating system"), "",
            "    AlmaLinux 9.6 (Sage Margay) · kernel 5.14.0-570",
            "    {d}Last checked 10 minutes ago{/}", ""]
    if state == "available":
        body += ["    {y}▲{/} 23 updates available, {y}4 for security{/}",
                 "    {d}Includes a new kernel: a restart is needed afterwards.{/}", "",
                 "    {d}OpenVIBES keeps running while packages update; it restarts{/}",
                 "    {d}only the services whose packages changed.{/}"]
    elif state == "running":
        body += ["    {t}⠹{/} Updating 23 packages… {d}(14 of 23: openssl-libs){/}",
                 "    {d}This takes a few minutes. You can leave this screen: it{/}",
                 "    {d}carries on and Home shows when it is done.{/}"]
    elif state == "reboot":
        body += ["    {g}✓{/} 23 packages updated (3 min 12 s)",
                 "    {y}▲{/} A restart is needed for the new kernel.",
                 "    {d}OpenVIBES starts again by itself after the restart;{/}",
                 "    {d}agents keep their findings meanwhile.{/}"]
    return screen("limebox · Maintenance › Operating system", body, bar_lines)


shots = [
    ("Maintenance with the operating system", "A new second entry: the OS, how many updates, how many for security.",
     maint(1)),
    ("Enter: Operating system", "What is installed, what is waiting, and what will happen.",
     os_screen(bar("{k} u {/} Update everything  {k} c {/} Check again"))),
    ("Press u", "The bar asks, and says what it means.",
     os_screen(ask("Install 23 updates?", "restart after"))),
    ("While it updates", "Progress on the screen and in the bar; leaving the screen does not stop it.",
     os_screen(bar("{t}⠹{/} Updating the operating system…"), "running")),
    ("Done: restart needed", "The bar offers the restart; Home keeps showing it until you do.",
     os_screen(bar("{k} r {/} Restart now  {k} l {/} Later"), "reboot")),
]

print(page("Appliance: operating system updates",
           "On the appliance you SSH in and land on Home. Maintenance gets an Operating system entry "
           "(AlmaLinux or Rocky, both dnf). Reply per number: yes, or what to change.", shots))
