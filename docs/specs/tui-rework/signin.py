"""#565: the appliance's console signs in on an OpenVIBES screen, not
`localhost login:`, then opens Home; Log out comes back here."""

import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import bar, header, menu, page, screen  # noqa: E402

gen.UPDATE = None
gen.VERSION = "v0.3.2"

HOME = [("Status", "health, services, logs"),
        ("Maintenance", "updates, repair, ports, certificates, backup"),
        ("System", "network, time, login, restart"), ("Log out", "")]
WHERE = "    {d}The console: https://openvibes-va.lime.lab · SSH: lime@192.168.1.50{/}"


def signin(account, password, at, note="", red=False):
    """at: 0 Account, 1 Password, 2 Sign in; the row typed shows █."""
    rows = [("Account", account + ("█" if at == 0 else "")),
            ("Password", "•" * password + ("█" if at == 1 else "")),
            ("Sign in", "opens the menu")]
    body = [header("Sign in to this appliance"), ""] + menu(rows, at, 18) + ["", ""]
    body.append(f"    {{r}}{note}{{/}}" if red else f"    {{d}}{note}{{/}}")
    body += ["", WHERE]
    keys = "{k} Enter {/} Sign in" if at == 2 else "{k} Enter {/} Next"
    return screen("openvibes-va · Sign in", body, bar(keys, "", nav=True))


def home(sel):
    body = ["    {g}●{/} All 8 services running", ""] + menu(HOME, sel, 15)
    return screen("openvibes-va · lime", body, bar("{k} Enter {/} Open", "{k} ? {/}"))


print(page("Appliance: the console signs in on an OpenVIBES screen (#565)",
           "Reply per number: yes, or what to change.", [
    ("After the appliance starts", "Instead of 'localhost login:'. The cursor types the account at once.",
     signin("", 0, 0, "The account made when the appliance was installed, or another one.")),
    ("Type lime, Enter", "The password next; it shows only dots.",
     signin("lime", 0, 1, "Its password. Three wrong ones lock the account for 10 minutes.")),
    ("Type a wrong password, Enter twice", "Said under the list; the password is cleared, the account kept.",
     signin("lime", 0, 1, "✗ Wrong account or password. 2 tries left before a 10-minute lock.", red=True)),
    ("Type the right one, Enter twice", "Home, as lime. The location line names the account.", home(0)),
    ("⭣ three times, Enter: Log out", "Back to this screen, empty, for the next person.",
     signin("", 0, 0, "The account made when the appliance was installed, or another one.")),
]))
