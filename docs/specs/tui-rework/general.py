import html
import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import ask, bar, header, menu, page, pad, render_line, screen  # noqa: E402

LEFT = [("⭡⭣", "move · lists scroll"), ("Enter", "open, change, confirm"),
        ("Space", "select or deselect"), ("⭠⭢", "Yes or No in a question")]
RIGHT = [("Esc", "back, or cancel"), ("?", "this help"), ("q", "quit, from Home"), ("", "")]


def key_rows():
    rows = []
    for (lk, ld), (rk, rd) in zip(LEFT, RIGHT):
        left = pad(f"{{k}} {lk} {{/}}", 9) + " " + pad(ld, 24)
        right = (pad(f"{{k}} {rk} {{/}}", 7) + " " + rd) if rk else ""
        rows += ["    " + left + "   " + right, ""]
    return rows[:-1]


help_screen = screen("limebox · Help", [header("Keys"), ""] + key_rows() + ["",
                     "    {d}Here (Update OpenVIBES): Enter on Update now updates; Space{/}",
                     "    {d}ticks Back up first.{/}"], bar("", "{k} Esc {/} Close", nav=False))

failed = screen("limebox · Maintenance › Update OpenVIBES", [header("Updating to 0.2.9"), "",
    "    {g}✓{/} Back up", "    {g}✓{/} Stop services", "    {r}✗{/} {b}Install packages{/}",
    "    {d}· Update the database{/}", "    {d}· Start services{/}", "",
    "    {r}The package repository could not be reached:{/}",
    "    {r}repo.openvibes.org timed out after 30 s.{/}",
    "    {d}Check the network or the proxy, then try again. The services are{/}",
    "    {d}started again as they were; nothing was changed.{/}"],
    bar("{k} Enter {/} Try again", "{k} Esc {/} Back  {k} ? {/}", nav=False))

wrong_pw = screen("limebox · Install › Review", [header("Review"), "",
    "    {d}…your choices…{/}", ""] + menu([("Install", "asks for your password once")], 0, 24),
    bar("{r}Wrong password, 2 tries left.{/} {b}Password:{/} █", "{k} Esc {/} Back", nav=False))

running_quit = screen("limebox · Maintenance › Operating system", [header("Operating system"), "",
    "    {t}⠹{/} Updating 23 packages… {d}(14 of 23){/}"],
    ask("Quit while the update runs?", "it keeps running"))

SIGNIN = [("Reset the admin password", "a new password, shown once"),
          ("Single sign-on", "{g}on{/} · SAML, Lime Lab identity provider")]
signin = screen("limebox · Maintenance › Console sign-in", [header("Console sign-in"), "",
    "    {d}For when nobody can sign in to the console any more.{/}", ""] + menu(SIGNIN, 1, 26) + ["",
    "    {d}With single sign-on, the local admin still works as a break-glass account.{/}"],
    bar("{k} Enter {/} Turn single sign-on off"))


def small():
    lines = [""] * 6 + ["{y}This window is 60×18.{/}", "OpenVIBES needs at least 80×24:", "make the window larger."]
    out = []
    for l in lines:
        t = gen.TAG.sub("", l)
        padl = (60 - len(t)) // 2
        out.append(render_line(" " * padl + l)[:])
    return "\n".join(o[: o.rfind(" " * 20)] if False else o for o in out)


print(page("Everywhere: help, errors, small windows, quitting, sign-in",
           "Reply per number: yes, or what to change.", [
    ("? on any screen: Help", "Every key, plus what the keys do on the screen you came from.", help_screen),
    ("A step fails", "Red, in plain words: what failed, why, what to do, and that nothing was broken.", failed),
    ("A wrong password", "Said in the bar, with the tries left.", wrong_pw),
    ("q while something runs", "It asks; the work carries on either way.", running_quit),
    ("Maintenance › Console sign-in", "Single sign-on is set up in the console; here you can turn it off if it breaks.", signin),
    ("A window that is too small", "One clear sentence instead of a broken screen.", small()),
]))
