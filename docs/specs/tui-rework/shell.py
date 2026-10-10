import html
import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import ask, bar, header, menu, page, render_line, screen  # noqa: E402

MAINT = [("Update OpenVIBES", "0.2.9 is available"),
         ("Operating system", "AlmaLinux 9.6 · 23 updates, 4 for security"),
         ("Repair", "check every step, fix what is wrong"),
         ("Optional parts", "agent on this host · assistant"),
         ("Ports and addresses", "console 8443, agents 18423 and 18424, devices 514"),
         ("Certificates", "agents: your PKI · web: ACME"),
         ("Database", "schema 46 · 3.1 GB · cleaned up nightly"),
         ("Console sign-in", "reset the admin password · single sign-on"),
         ("Back up", "save the database to a folder you choose"),
         ("Shell", "the operating system's command line, for experts"),
         ("Uninstall", "remove OpenVIBES from this host")]


def maint(sel, top, b):
    shown = 5
    body = [header("Maintenance"), f"    {{d}}⭡ {top} more{{/}}" if top else ""]
    body += menu(MAINT[top:top + shown], sel - top, 22)
    rest = len(MAINT) - top - shown
    body.append(f"    {{d}}⭣ {rest} more{{/}}" if rest > 0 else "")
    return screen("openvibes-va · Maintenance", body, b)


def term(lines):
    out = []
    for l in lines + [""] * (gen.H - len(lines)):
        out.append(render_line(l))
    return "\n".join(out)


shell = term([
    "{t}OpenVIBES shell{/} · {d}type{/} {b}exit{/} {d}to go back to the menu. Logged as admin, 21:42.{/}",
    "{d}Changes here are yours: Repair can put OpenVIBES' own files right again.{/}",
    "",
    "[admin@openvibes-va ~]$ systemctl status openvibes-ingest --no-pager | head -3",
    "● openvibes-ingest.service - OpenVIBES ingest",
    "     Loaded: loaded (/usr/lib/systemd/system/openvibes-ingest.service; enabled)",
    "     Active: {g}active (running){/} since Sat 2026-10-10 18:40:02 CEST; 3h ago",
    "[admin@openvibes-va ~]$ exit",
])

print(page("Maintenance › Shell", "Reply per number: yes, or what to change.", [
    ("Maintenance, scrolled to Shell", "Second to last, before Uninstall.",
     maint(9, 6, bar("{k} Enter {/} Open the shell"))),
    ("Enter: the warning", "Experts only; it asks for your login password next.",
     maint(9, 6, ask("Open a shell?", "for experts; logged"))),
    ("Yes, password: the shell", "A plain shell; one line says how to get back.", shell),
    ("exit: back where you were", "Maintenance, Shell still highlighted.", maint(9, 6, bar("{k} Enter {/} Open the shell"))),
]))
