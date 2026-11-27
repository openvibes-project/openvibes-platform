"""#567: the appliance's automatic updates (Appliance settings) and the
manual update from a GitHub release (Maintenance › Update OpenVIBES), per
Decision #664: one signed update file per release; the OS from
AlmaLinux's mirrors through dnf-automatic."""

import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import ask, bar, checkbar, header, menu, page, screen  # noqa: E402

gen.UPDATE = "0.3.3"
gen.VERSION = "v0.3.2"

HOME = [("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, database, backup"),
        ("Appliance settings", "network, time, SSH, updates, OS access"), ("Log out", "")]
SETTINGS = [("Network", "192.168.1.50 · DHCP · openvibes-va.lime.lab"),
            ("Time", "in sync · pool.ntp.org · Europe/Stockholm"),
            ("SSH", "keys, and the first account's password"),
            ("Updates", "OpenVIBES and security fixes · 03:00–05:00"),
            ("Login password", "change it for this account"),
            ("OS access", "the operating system's command line"),
            ("Restart", ""), ("Shut down", "")]


def home(sel):
    body = ["    {g}●{/} All 8 services running   {y}▲{/} 0.3.3 installs tonight, 03:00–05:00", ""] + menu(HOME, sel, 20)
    return screen("openvibes-va · lime", body, bar("{k} Enter {/} Open", "{k} ? {/}"))


def settings(sel, top, b=None):
    shown = 5
    body = [header("Appliance settings"), f"    {{d}}⭡ {top} more{{/}}" if top else ""]
    body += menu(SETTINGS[top:top + shown], sel - top, 20)
    rest = len(SETTINGS) - top - shown
    body.append(f"    {{d}}⭣ {rest} more{{/}}" if rest > 0 else "")
    return screen("openvibes-va · Appliance settings", body, b or bar("{k} Enter {/} Open"))


AUTO_HELP = [
    "Checked against OpenVIBES' key, backed up first, installed in the window.",
    "Space: security fixes only, everything, or none. From AlmaLinux's mirrors.",
    "When updates may install, every day. Enter types it, as 03:00–05:00.",
    "A new kernel needs a restart; it happens only inside the window.",
    "Checked first: the window must be at least an hour.",
]


def auto(sel, os="security fixes only", window="03:00–05:00", apply="nothing changed", typing=False,
         b=None, changed=False):
    tick = "{g}[x]{/}"
    rows = [(f"{tick} New OpenVIBES releases", "backed up first, then installed"),
            ("Operating system", os + ("" if typing else "")),
            ("Window", window + ("█" if typing else "")),
            (f"{tick} Restart when needed", "inside the window only"),
            ("Apply", apply)]
    rows = [(n.replace("{g}", "").replace("{/}", "") if i == sel else n, v) for i, (n, v) in enumerate(rows)]
    if changed:
        rows[1] = ("* " + rows[1][0], rows[1][1])
    body = [header("Updates"), ""] + menu(rows, sel, 28) + ["", f"    {{d}}{AUTO_HELP[sel]}{{/}}"]
    return screen("openvibes-va · Appliance settings › Updates", body, b)


UPD_INFO = ["    v0.3.2 installed · {y}0.3.3 available{/} {d}· released 2 Dec · checked 21:40{/}",
            "    {d}New: offline updates over SFTP · faster vulnerability lists · fixes{/}", ""]


def update(sel, b, info=None, hint=None):
    rows = [("{g}[x]{/} Back up first", "/var/lib/openvibes/backups, a new file each time"),
            ("Update now", "once GitHub can be reached" if info else "downloads 312 MB, checks its signature"),
            ("What's new", "the release notes"), ("Check again", "asks GitHub for the newest release")]
    rows = [(n.replace("{g}", "").replace("{/}", "") if i == sel else n, v) for i, (n, v) in enumerate(rows)]
    body = [header("Update OpenVIBES"), ""] + (info or UPD_INFO) + menu(rows, sel, 22)
    if hint:
        body += ["", hint]
    if info:
        gen.UPDATE = None
    out = screen("openvibes-va · Maintenance › Update OpenVIBES", body, b)
    gen.UPDATE = "0.3.3"
    return out


STEPS = ["Download the update file", "Check its signature", "Back up", "Stop services",
         "Install packages", "Update the database", "Start services", "Ready"]


def progress(done, detail, finished=False):
    body = [header("Updating to 0.3.3"), ""]
    for i, s in enumerate(STEPS):
        if i < done or finished:
            body.append(f"    {{g}}✓{{/}} {s}")
        elif i == done:
            body.append(f"    {{t}}⠹{{/}} {{b}}{s}{{/}}  {{d}}{detail}{{/}}")
        else:
            body.append(f"    {{d}}· {s}{{/}}")
    if finished:
        body += ["", "    {g}✓ Updated to 0.3.3 · everything is ready (4 min 12 s){/}"]
        gen.UPDATE = None
        out = screen("openvibes-va · Maintenance › Update OpenVIBES", body,
                     bar("{k} Enter {/} Back to Maintenance", "", nav=False))
        gen.UPDATE = "0.3.3"
        return out
    return screen("openvibes-va · Maintenance › Update OpenVIBES", body,
                  bar(f"{{t}}⠹{{/}} Step {done + 1} of {len(STEPS)}: {STEPS[done]}", "", nav=False))


OFFLINE = ["    v0.3.2 installed · {r}GitHub cannot be reached{/} {d}· checked 21:40{/}",
           "    {d}No network, or it blocks github.com. Appliance settings › Network shows it.{/}", ""]

print(page("Appliance: automatic and manual updates (#567)",
           "Reply per number: yes, or what to change.", [
    ("Home, the evening a release came out", "The status line says when it installs.", home(0)),
    ("Appliance settings", "A new entry under SSH says what updates by itself, and when.", settings(3, 1)),
    ("Enter: Updates", "As the appliance comes: both on, security fixes only for the OS, 03:00–05:00.",
     auto(0, b=checkbar())),
    ("⭣, Space: everything", "Space steps through security fixes only · everything · none. The changed row is marked.",
     auto(1, os="everything", apply="1 change: the operating system", changed=True,
          b=bar("{k} Space {/} Change  {k} Enter {/} Confirm"))),
    ("⭣, Enter on Window: type it", "Typed in place, checked as typed.",
     auto(2, os="everything", window="02:00–04:00", typing=True, changed=True,
          b=bar("{b}Window:{/} type HH:MM–HH:MM  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False))),
    ("⭣⭣, Enter on Apply: the question", "",
     auto(4, os="everything", window="02:00–04:00", apply="2 changes", changed=True,
          b=ask("Change the updates?", "from tonight"))),
    ("Maintenance › Update OpenVIBES", "On the appliance the release comes from GitHub, as one signed file.",
     update(1, bar("{k} Enter {/} Update now"))),
    ("Enter on Update now: the question", "", update(1, ask("Update to 0.3.3?", "about 5 minutes"))),
    ("Updating", "Two new first steps: the download and its signature. A bad signature stops it there, nothing changed.",
     progress(0, "120 of 312 MB")),
    ("Done", "One result line.", progress(0, "", finished=True)),
    ("Without internet", "Says so; Check again tries once more.",
     update(3, bar("{k} Enter {/} Check again"), info=OFFLINE)),
]))
