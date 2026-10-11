import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, checkbar, header, menu, page, pad, screen  # noqa: E402


def strip(n):
    return n.replace("{g}", "").replace("{/}", "")


BK = [("Save to", "~/openvibes-backup-2026-10-10-2104.dump"), ("Back up now", "about 1 minute for 3.1 GB")]


def backup(sel, b, extra=None):
    body = [header("Back up"), "",
            "    {d}The database: findings, alarms, cases, users, settings. Certificates{/}",
            "    {d}and keys are not in it; Certificates keeps those.{/}", ""] + menu(BK, sel, 14)
    if extra:
        body += [""] + extra
    return screen("limebox · Maintenance › Back up", body, b)


def un(sel, everything=False, typed=None, b=None):
    items = [(("(•)" if not everything else "( )") + " Keep the data", "remove the programs; data stays for a reinstall"),
             (("(•)" if everything else "( )") + " Remove everything", "programs, data, accounts, certificates, settings"),
             ("{g}[x]{/} Back up first", "~/openvibes-backup-2026-10-10-2104.dump"),
             ("Uninstall", "")]
    if everything:
        items.insert(3, ("Type limebox to confirm", (typed or "") + ("█" if typed not in (None, "limebox") else " {g}✓{/}")))
    items = [(strip(n) if i == sel else n, v) for i, (n, v) in enumerate(items)]
    body = [header("Uninstall"), ""] + menu(items[:4] if not everything else items[1:5], sel if not everything else sel - 1, 26)
    if everything:
        body = [header("Uninstall"), "    {d}↑ 1 more{/}"] + menu(items[1:5], sel - 1, 26)
    body += ["", "    {d}Nothing is left behind: every account, file and firewall change goes.{/}" if everything else
             "    {d}PostgreSQL stays installed; it may serve other programs.{/}"]
    return screen("limebox · Maintenance › Uninstall", body, b)


print(page("Maintenance: Back up and Uninstall",
           "Key by key. Reply per number: yes, or what to change.", [
    ("Maintenance › Back up", "What is in a backup; a new file name every time.",
     backup(1, bar("{k} Enter {/} Back up now"))),
    ("Enter on Back up now", "", backup(1, bar("{t}⠹{/} Backing up… 1.4 of 3.1 GB", "", nav=False))),
    ("Done", "Where it is, how big, and what to do with it.",
     backup(1, bar("{k} Enter {/} Done", "", nav=False),
            ["    {g}✓{/} Saved {b}~/openvibes-backup-2026-10-10-2104.dump{/} (412 MB)",
             "    {d}Copy it off this host: a backup on the same disk does not survive the disk.{/}"])),
    ("Maintenance › Uninstall", "Keep the data is the default; back up is ticked.",
     un(0, b=checkbar())),
    ("↓, Space: Remove everything", "Typing the host name confirms it; nothing is left behind.",
     un(3, everything=True, typed="lime", b=bar("{b}Type the host name:{/} limebox  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False))),
    ("↓ to Uninstall, Enter", "", un(4, everything=True, typed="limebox",
                                     b=ask("Remove OpenVIBES and all its data?", "backup first"))),
]))
