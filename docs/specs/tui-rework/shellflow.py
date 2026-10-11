import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import shell
    import system2
from gen import ask, bar, page, render_line, screen  # noqa: E402
import gen  # noqa: E402

ssh = shell.term(["{d}$ ssh admin@openvibes-va.lime.lab{/}", "admin@openvibes-va.lime.lab's password: ", "",
                  "{d}… the TUI starts by itself …{/}"])
pw = shell.maint(9, 6, bar("{b}Your login password:{/} ••••••••█  {k} Enter {/} Open", "{k} Esc {/} Cancel", nav=False))

flow = [
    ("You SSH in", "The appliance's login opens the TUI; there is no prompt first.", ssh),
    ("Home", "Highlight on Status.", system2.home(0)),
    ("⭣ once", "Maintenance highlighted.", system2.home(1)),
    ("Enter: Maintenance", "The first five entries; ⭣ 6 more below.", shell.maint(0, 0, bar("{k} Enter {/} Open"))),
    ("⭣ nine times", "The list scrolls one row per step; Shell is second to last.",
     shell.maint(9, 6, bar("{k} Enter {/} Open the shell"))),
    ("Enter: the warning", "The standard question.", shell.maint(9, 6, ask("Open a shell?", "for experts; logged"))),
    ("Enter on Yes: your password", "Asked in the bar.", pw),
    ("Enter: the shell", "A plain command line; one line says how to get back.", shell.shell),
    ("exit", "Back on Maintenance, Shell still highlighted.", shell.maint(9, 6, bar("{k} Enter {/} Open the shell"))),
    ("Esc: Home, then ⭣⭣⭣ to Log out", "Log out ends the SSH session.", system2.home(3)),
]
print(page("Maintenance › Shell in context: from SSH login to log out",
           "Reply per number: yes, or what to change.", flow))
