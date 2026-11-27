"""#566: the appliance's System becomes Appliance settings, and OS access
opens the operating system at three levels (ruling #554): read only, user
(danger), root (bigger danger: a typed confirmation, no password)."""

import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import ask, bar, header, menu, page, render_line, screen  # noqa: E402

gen.UPDATE = None
gen.VERSION = "v0.3.2"

HOME = [("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, database, backup"),
        ("Appliance settings", "network, time, SSH, OS access, restart"), ("Log out", "")]
SETTINGS = [("Network", "192.168.1.50 · DHCP · openvibes-va.lime.lab"),
            ("Time", "in sync · pool.ntp.org · Europe/Stockholm"),
            ("SSH", "keys, and the first account's password"),
            ("Login password", "change it for this account"),
            ("OS access", "the operating system's command line"),
            ("Restart", ""), ("Shut down", "")]
LEVELS = [("Read only", "look at everything, change nothing"),
          ("{y}User{/}", "{y}danger:{/} a shell as lime"),
          ("{r}Root{/}", "{r}bigger danger:{/} a shell as root")]
HELP = ["Files, logs and services can be read; nothing can be written or started.",
        "Your account's own shell. What you change, OpenVIBES does not know about.",
        "Everything on this appliance can be changed, and nothing undoes it. Repair can put OpenVIBES' own files right again; nothing else."]


def home(sel):
    body = ["    {g}●{/} All 8 services running", ""] + menu(HOME, sel, 20)
    return screen("openvibes-va · lime", body, bar("{k} Enter {/} Open", "{k} ? {/}"))


def settings(sel, top, b=None):
    shown = 5
    body = [header("Appliance settings"), f"    {{d}}⭡ {top} more{{/}}" if top else ""]
    body += menu(SETTINGS[top:top + shown], sel - top, 18)
    rest = len(SETTINGS) - top - shown
    body.append(f"    {{d}}⭣ {rest} more{{/}}" if rest > 0 else "")
    return screen("openvibes-va · Appliance settings", body, b or bar("{k} Enter {/} Open"))


def strip(name):
    for tag in ("{y}", "{r}", "{/}"):
        name = name.replace(tag, "")
    return name


def levels(sel, b, note=None, red=False):
    rows = [(strip(n) if i == sel else n, strip(v) if i == sel else v) for i, (n, v) in enumerate(LEVELS)]
    body = [header("OS access"), ""] + menu(rows, sel, 18) + ["", ""]
    text = note or HELP[sel]
    colour = "{r}" if red else "{d}"
    words, line = text.split(), "    "
    for word in words:
        if len(line) + len(word) > 76:
            body.append(f"{colour}{line.rstrip()}{{/}}")
            line = "    "
        line += word + " "
    body.append(f"{colour}{line.rstrip()}{{/}}")
    return screen("openvibes-va · Appliance settings › OS access", body, b)


def term(lines):
    return "\n".join(render_line(l) for l in lines + [""] * (gen.H - len(lines)))


read_only = term([
    "{t}OS access, read only{/} · {d}type{/} {b}exit{/} {d}to go back to the menu. Logged as lime, 21:42.{/}",
    "{d}Everything can be read; nothing can be written, started or stopped.{/}",
    "",
    "[lime@openvibes-va ~]$ journalctl -u openvibes-ingest -n 2 --no-pager",
    "Nov 27 21:40:11 openvibes-va openvibes-ingest[1123]: agent web-01 reported",
    "Nov 27 21:41:02 openvibes-va openvibes-ingest[1123]: agent db-02 reported",
    "[lime@openvibes-va ~]$ touch /etc/x",
    "touch: cannot touch '/etc/x': Read-only file system",
    "[lime@openvibes-va ~]$ █",
])
user = term([
    "{t}OS access{/} {y}as lime{/} · {d}type{/} {b}exit{/} {d}to go back to the menu. Logged, 21:44.{/}",
    "{y}Danger: what you change here, OpenVIBES does not know about.{/}",
    "",
    "[lime@openvibes-va ~]$ █",
])
root = term([
    "{t}OS access{/} {r}as root{/} · {d}type{/} {b}exit{/} {d}to go back to the menu. Logged as lime, 21:46.{/}",
    "{r}Bigger danger: everything can be changed, and nothing undoes it.{/}",
    "",
    "[root@openvibes-va ~]# █",
])

TYPE = "{b}Type{/} {r}root{/} {b}to open it:{/} "

print(page("Appliance: Appliance settings and OS access (#566)",
           "Reply per number: yes, or what to change.", [
    ("Home", "System is now Appliance settings, as the ruling names it.", home(2)),
    ("Enter: Appliance settings", "The same entries as System, plus OS access. "
     "On the appliance, Maintenance has no Shell any more: OS access replaces it.",
     settings(0, 0)),
    ("⭣ four times", "The list scrolls one row per step; OS access is above Restart.",
     settings(4, 2, bar("{k} Enter {/} Open"))),
    ("Enter: OS access", "Three levels. The help line says what each one allows.",
     levels(0, bar("{k} Enter {/} Open"))),
    ("Enter on Read only: the question", "The standard question, Yes first.",
     levels(0, ask("Open a read-only shell?", "logged"))),
    ("Yes: the read-only shell", "Your account's shell with every file system read only "
     "and no rights to change anything (systemd's sandbox). exit returns to OS access.", read_only),
    ("⭣ to User, Enter: the question", "Danger, so the question starts on No.",
     levels(1, ask("Open a shell as lime?", "danger: OpenVIBES does not see what you change", yes=False))),
    ("⭠, Enter on Yes: the user shell", "No second password: you signed in already.", user),
    ("⭣ to Root, Enter: type root", "Bigger danger: no question, a typed word, and the warning in red. No password.",
     levels(2, bar(TYPE + "█  {k} Enter {/} Open", "{k} Esc {/} Cancel", nav=False),
            note=HELP[2], red=True)),
    ("Type root, Enter: the root shell", "Anything else typed does nothing; Esc cancels.", root),
]))
