import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import bar, header, menu, page, screen  # noqa: E402

gen.UPDATE = None  # a fresh install is the newest version

# User: choosing comes first; quick settings suit homelabs only.
WELCOME = [("Choose what to install", "components, names, ports"),
           ("Quick install", "everything, with default names and ports"),
           ("Quit", "")]


def welcome(sel):
    body = ["    This host does not run OpenVIBES yet.", "",
            ] + menu(WELCOME, sel, 24)
    return screen("limebox · Install", body, bar("{k} Enter {/} Open", "{k} q {/} Quit  {k} ? {/}"))


OPTIONS = [
    ("[x] Console", "the web interface (always)"),
    ("[x] Agent connections", "agents report here (always)"),
    ("[x] Vulnerabilities", "match packages against advisories"),
    ("[x] Rule distribution", "send signed rules to agents"),
    ("[ ] Assistant", "local AI helper, 2.7 GB download"),
    ("Host name", "limebox.lan"),
    ("Other names", "none"),
    ("Console port", "443"),
    ("Install", "with these choices"),
]
OPT_HELP = {
    0: "The console is how you use OpenVIBES; it is always installed.",
    4: "Answers questions about your findings on this host, no cloud. Needs 4 GB.",
    5: "The name agents and your browser use to reach this host.",
    8: "Starts the install; it asks for your password once.",
}


def options(sel, top=0, shown=5, editing=None):
    body = [header("Choose what to install")]
    body.append(f"    {{d}}↑ {top} more{{/}}" if top else "")
    rows = []
    for i, (name, desc) in enumerate(OPTIONS[top:top + shown], top):
        if name.startswith("["):
            box, label = name[:3], name[4:]
            box = box.replace("[x]", "{g}[x]{/}") if i != sel else box
            name_txt = f"{label}"
        else:
            box, name_txt = "   ", name
        val = desc + ("█" if editing == i else "")
        if i == sel:
            rows.append(f"  {{s}}▸ {box} {name_txt:<20} {val:<44}{{/}}")
        else:
            rows.append(f"    {box} {name_txt:<20} {{d}}{val}{{/}}")
        rows.append("")
    body += rows[:-1]
    rest = len(OPTIONS) - top - shown
    body.append(f"    {{d}}↓ {rest} more{{/}}" if rest > 0 else "")
    body.append("    {d}" + OPT_HELP.get(sel, "") + "{/}")
    return body


STEPS = ["Packages", "PostgreSQL", "Database", "Certificate authority", "Certificates",
         "Console", "Services", "Firewall", "Ready"]


def progress(done, detail):
    body = [header("Installing"), ""]
    for i, step in enumerate(STEPS):
        if i < done:
            body.append(f"    {{g}}✓{{/}} {step}")
        elif i == done:
            body.append(f"    {{t}}⠹{{/}} {{b}}{step}{{/}}  {{d}}{detail}{{/}}")
        else:
            body.append(f"    {{d}}· {step}{{/}}")
    return screen("limebox · Install", body, bar("{t}⠹{/} " + f"Step {done + 1} of {len(STEPS)}: {STEPS[done]}", "", nav=False))


finished = screen("limebox · Install", [
    header("OpenVIBES is installed"), "",
    "    Open the console    {b}https://limebox.lan{/}",
    "    Sign in as          {b}admin{/}",
    "    Password            {b}Kq7-vR2p-Xw9m{/}   {y}shown only now: write it down{/}", "",
    "    Root key            {b}~/openvibes-root-ca.key{/}",
    "                        {d}move it to a USB stick and keep it offline{/}", "",
    "    {d}Next: sign in, change the password, then add hosts under Enrollment.{/}",
], bar("{k} Enter {/} Continue to Home", "", nav=False))

shots = [
    ("First start: Welcome", "A fresh host opens here instead of Home; choosing comes first.", welcome(0)),
    ("↓ once: Quick install", "Says what it does: installs everything with the defaults.", welcome(1)),
    ("↑ back, Enter: the choices", "Components as checkboxes: Space selects. Then names and ports: Enter edits.",
     screen("limebox · Install", options(4), bar("{k} Space {/} Select"))),
    ("↓ to Host name, Enter: edit in place", "The line under the list explains each entry.",
     screen("limebox · Install", options(5, top=2, editing=5),
            bar("{b}Host name:{/} type the name  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False))),
    ("↓ to Install, Enter: your password", "Asked once, in the bar; never stored.",
     screen("limebox · Install", options(8, top=4),
            bar("{b}Your password (sudo):{/} ••••••••█  {k} Enter {/} Install", "{k} Esc {/} Back", nav=False))),
    ("Installing", "Every step and what it is doing now; the screen never freezes.",
     progress(0, "downloading 14 of 31 packages")),
    ("Later in the install", "Done steps get a ✓.", progress(5, "starting the web interface")),
    ("Finished", "Labelled, nothing cut off; the password shown once.", finished),
]
print(page("First install, key by key",
           "What a host without OpenVIBES shows. Reply per number: yes, or what to change.", shots))
