import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, header, menu, page, screen  # noqa: E402

INFO = [header("Operating system"), "",
        "    AlmaLinux 9.6 (Sage Margay) · kernel 5.14.0-570 · checked 10 min ago",
        "    {y}▲{/} 23 updates available, {y}4 for security{/} · includes a new kernel", ""]
ACTIONS = [("Update everything", "23 packages, then a restart"), ("Check again", "")]


def os_screen(sel, bar_lines):
    return screen("limebox · Maintenance › Operating system", INFO + menu(ACTIONS, sel), bar_lines)


print(page("Operating system: arrows instead of letters",
           "The actions are entries in the screen: ↑↓ to choose, Enter to do it. Reply: yes, or what to change.", [
    ("Enter: Operating system", "The highlight starts on the first action.",
     os_screen(0, bar("{k} Enter {/} Update everything"))),
    ("Press ↓", "The highlight moves to Check again; the bar follows.",
     os_screen(1, bar("{k} Enter {/} Check again"))),
    ("↑ back, Enter on Update everything", "The bar asks first, as before.",
     os_screen(0, ask("Install 23 updates?", "A restart is needed after"))),
]))
