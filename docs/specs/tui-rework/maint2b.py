import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, checkbar, header, menu, page, screen  # noqa: E402

# Sub-project 2b: the screens the approved mockups did not cover yet.
# Maintenance as it stands after 2b (Operating system comes in step 5).
HOME = [("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, ports, certificates, backup"), ("Quit", "")]
MAINT = [("Update OpenVIBES", "0.2.9 is available"),
         ("Repair", "check every step, fix what is wrong"),
         ("Optional parts", "agent on this host · assistant"),
         ("Ports and addresses", "console 8443, agents 18423 and 18424, devices 514"),
         ("Certificates", "signed by Lime Lab Root CA · until 2028-10-10"),
         ("Database", "schema 53 · 3.1 GB · cleaned up nightly"),
         ("Console sign-in", "reset the admin password"),
         ("Back up", "save the database to a folder you choose"),
         ("Shell", "the operating system's command line, for experts"),
         ("Uninstall", "remove OpenVIBES from this host")]
PW = "{b}Your password (sudo):{/} ••••••••█  {k} Enter {/} "


def home(sel):
    body = ["    {g}●{/} All 8 services running", ""] + menu(HOME, sel, 15)
    return screen("limebox", body, bar("{k} Enter {/} Open", "{k} q {/} Quit  {k} ? {/}"))


def maint(sel, top=0):
    shown = 5
    body = [header("Maintenance"), f"    {{d}}⭡ {top} more{{/}}" if top else ""]
    body += menu(MAINT[top:top + shown], sel - top)
    rest = len(MAINT) - top - shown
    body.append(f"    {{d}}⭣ {rest} more{{/}}" if rest > 0 else "")
    return screen("limebox · Maintenance", body, bar("{k} Enter {/} Open"))


def steps(where, title, names, done, detail, result=None):
    body = [header(title), ""]
    for i, s in enumerate(names):
        if result or i < done:
            body.append(f"    {{g}}✓{{/}} {s}")
        elif i == done:
            body.append(f"    {{t}}⠹{{/}} {{b}}{s}{{/}}  {{d}}{detail}{{/}}")
        else:
            body.append(f"    {{d}}· {s}{{/}}")
    if result:
        body += ["", f"    {{g}}✓ {result}{{/}}"]
        return screen(where, body, bar("{k} Enter {/} Back", "", nav=False))
    return screen(where, body, bar(f"{{t}}⠹{{/}} Step {done + 1} of {len(names)}: {names[done]}", "", nav=False))


# Optional parts ---------------------------------------------------------
OPT = "limebox · Maintenance › Optional parts"


def strip(n):
    return n.replace("{g}", "").replace("{/}", "").replace("{y}", "")


def opt(sel, agent=True, assistant=False, note="nothing changed yet", b=None, help_=None):
    items = [(("{g}[x]{/}" if agent else "[ ]") + " Agent on this host", "watch this host too"),
             (("{g}[x]{/}" if assistant else "[ ]") + " Assistant", "local AI helper · 2.7 GB download"),
             ("Apply", note)]
    items = [(strip(n) if i == sel else n, v) for i, (n, v) in enumerate(items)]
    helps = {0: "The agent reports this host's own findings and alarms.",
             1: "Answers questions about your findings, on this host, no cloud. Needs 4 GB.",
             2: "Installs or removes what you changed above."}
    body = [header("Optional parts"), ""] + menu(items, sel, 26) + ["", "    {d}" + (help_ or helps[sel]) + "{/}"]
    return screen(OPT, body, b or (checkbar() if sel < 2 else bar("{k} Enter {/} Apply")))


ADD = ["Save the choice", "Install the assistant", "Download the model", "Start the assistant", "Ready"]
DROP = ["Save the choice", "Stop the agent", "Remove the agent", "Remove its data", "Ready"]

# Ports and addresses ----------------------------------------------------
PORTS = "limebox · Maintenance › Ports and addresses"


def ports(sel, rows, b, helptext):
    body = [header("Ports and addresses"), ""] + menu(rows, sel, 22) + ["", "    " + helptext]
    return screen(PORTS, body, b)


P = [("Console", "8443 · https://limebox.lan:8443"), ("Agent connections", "18423"),
     ("Rule distribution", "18424"), ("Network devices", "514/udp")]
P_TAKEN = [("Console", "8443"), ("Agent connections", "8080█"), ("Rule distribution", "18424"),
           ("Network devices", "514/udp")]
P_EDIT = [("Console", "8443"), ("Agent connections", "18500█"), ("Rule distribution", "18424"),
          ("Network devices", "514/udp")]
P_CHANGED = [("Console", "8443"), ("{y}*{/} Agent connections", "18500 · was 18423"),
             ("Rule distribution", "18424"), ("Network devices", "514/udp"),
             ("Apply", "agents must be told the new port")]
TYPE = bar("{b}Agent connections:{/} type a port  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False)
MOVE = ["Save the ports", "Open the new port", "Restart agent connections", "Close the old port", "Ready"]

# Certificates -----------------------------------------------------------
CERTS = "limebox · Maintenance › Certificates"
INFO = ["    Web and agents             valid until 2028-10-10 · 721 days left",
        "    Names                      limebox.lan, 192.168.1.10",
        "    Intermediate               signed by Lime Lab Root CA · until 2031-10-10", ""]


def certs(b=None):
    body = [header("Certificates"), ""] + INFO + menu([("Names", "add or remove a name agents use")], 0, 26)
    body += ["", "    {d}Names agents and browsers may use to reach this host.{/}"]
    return screen(CERTS, body, b or bar("{k} Enter {/} Names"))


NAMES = "limebox · Maintenance › Certificates › Names"


def names(sel, rows, b, helptext):
    body = [header("Names"), ""] + menu(rows, sel, 22) + ["", "    " + helptext]
    return screen(NAMES, body, b)


N = [("Host name", "limebox.lan"), ("Other name", "192.168.1.10"), ("Add a name", "an address or DNS name")]
N_TYPING = [("Host name", "limebox.lan"), ("Other name", "192.168.1.10"), ("Other name", "openvibes.lime.lan█"),
            ("Add a name", "an address or DNS name")]
N_BAD = [("Host name", "limebox.lan"), ("Other name", "192.168.1.10"), ("Other name", "Open Vibes█"),
         ("Add a name", "an address or DNS name")]
N_ADDED = [("Host name", "limebox.lan"), ("Other name", "192.168.1.10"),
           ("{y}*{/} Other name", "openvibes.lime.lan · new"), ("Add a name", "an address or DNS name"),
           ("Apply", "new certificates with these names")]
NSTEPS = ["Save the names", "New certificates", "Restart services", "Ready"]
NAME_BAR = bar("{b}Other name:{/} type a name  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False)

# Console sign-in --------------------------------------------------------
SIGN = "limebox · Maintenance › Console sign-in"


def signin(b, shown=False):
    body = [header("Console sign-in"), "", "    For when nobody can sign in to the console any more.", ""]
    if shown:
        body += ["    Sign in as                 admin",
                 "    New password               {b}Tz4m-W8qH-n2cR-7kLp{/}  {d}shown only now{/}", "",
                 "    {d}You are asked to change it at the next sign-in.{/}"]
    else:
        body += menu([("Reset the admin password", "a new password, shown once")], 0, 26)
    return screen(SIGN, body, b)


print(page("Maintenance 2b: the screens still missing",
           "Key by key from Home. Reply per number: yes, or what to change.", [
    ("Home", "Where every flow below starts.", home(0)),
    ("⭣, Enter: Maintenance", "The list after 2b: ten entries (Operating system comes later).", maint(0)),
    ("⭣ twice: Optional parts", "", maint(2)),
    ("Enter: Optional parts", "As approved.", opt(0)),
    ("⭣, Space: tick Assistant", "As approved.", opt(1, assistant=True, note="install the assistant")),
    ("⭣ to Apply, Enter: the question", "As approved.",
     opt(2, assistant=True, note="install the assistant", b=ask("Install the assistant?", "2.7 GB"))),
    ("Yes: your password", "Asked in the bar, like Update and Repair.",
     opt(2, assistant=True, note="install the assistant", b=bar(PW + "Install", "{k} Esc {/} Cancel", nav=False))),
    ("Enter: it runs", "The same step list as Update; leaving the screen does not stop it.",
     steps(OPT, "Installing the assistant", ADD, 2, "1.2 of 2.7 GB")),
    ("Done", "One result line.",
     steps(OPT, "Installing the assistant", ADD, 0, "", "Assistant installed · ask it in the console (6 min 12 s)")),
    ("Back on Optional parts, Space on the agent: untick it", "Removing says what goes with it.",
     opt(0, agent=False, assistant=True, note="remove the agent",
         help_="Removing the agent also removes its data from this host.")),
    ("⭣ twice to Apply, Enter: the question", "Starts on No: removing is never a stray Enter.",
     opt(2, agent=False, assistant=True, note="remove the agent",
         b=ask("Remove the agent?", "its data goes too", yes=False))),
    ("Yes, password: done", "Nothing of the agent is left on this host.",
     steps(OPT, "Removing the agent", DROP, 0, "", "Agent removed · nothing of it is left on this host (14 s)")),
    ("Maintenance › Ports and addresses, Enter on Agent connections, type 8080", "Taken: said at once, in red.",
     ports(1, P_TAKEN, TYPE, "{r}✗ 8080 is used by another program on this host: choose another.{/}")),
    ("Backspace, type 18500", "Free: as approved.", ports(1, P_EDIT, TYPE, "{d}18500 is free on this host.{/}")),
    ("Enter, ⭣ to Apply", "As approved.",
     ports(4, P_CHANGED, bar("{k} Enter {/} Apply"),
           "{d}Agents on other hosts need their install line again after this.{/}")),
    ("Enter: the question", "Says the consequence once more.",
     ports(4, P_CHANGED, ask("Move agents to 18500?", "new install line"),
           "{d}Agents on other hosts need their install line again after this.{/}")),
    ("Yes, password: it runs, then done", "The result says what to do next.",
     steps(PORTS, "Moving agent connections", MOVE, 0, "",
           "Moved to 18500 · new install line: console › Enrollment (9 s)")),
    ("Maintenance › Certificates", "Today's truth: the dates, no automatic renewal yet (that comes with step 4).",
     certs()),
    ("Enter: Names", "Each name is an entry; Enter edits it, an empty name removes it.",
     names(0, N, bar("{k} Enter {/} Change"), "{d}The name this host is known by.{/}")),
    ("⭣ twice, Enter on Add a name: type openvibes.lime.lan", "Checked as you type.",
     names(2, N_TYPING, NAME_BAR, "{d}A valid DNS name.{/}")),
    ("A name that cannot be used", "Said at once, in red; Enter does nothing.",
     names(2, N_BAD, NAME_BAR, "{r}✗ Not a DNS name or an address: letters, digits, dots and dashes.{/}")),
    ("Enter on a good name, ⭣ to Apply", "",
     names(4, N_ADDED, bar("{k} Enter {/} Apply"), "{d}Agents keep working; browsers see the new names.{/}")),
    ("Enter, Yes, password: done", "",
     steps(NAMES, "New certificates", NSTEPS, 0, "", "New certificates with 3 names · valid until 2028-10-20 (11 s)")),
    ("Maintenance › Console sign-in", "As approved.",
     signin(bar("{k} Enter {/} Reset the admin password"))),
    ("Enter, Yes, password: the new password", "As approved, with a password long enough for the console (15+).",
     signin(bar("{k} Enter {/} Done", "", nav=False), shown=True)),
]))
