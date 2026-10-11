import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import maint1
from gen import checkbar, header, menu, page, screen  # noqa: E402


def strip(n):
    return n.replace("{g}", "").replace("{/}", "")


def un(sel, ticked, note, hint=None):
    items = [("(•) Keep the data", "remove the programs; data stays for a reinstall"),
             ("( ) Remove everything", "programs, data, accounts, certificates, settings"),
             ((("{g}[x]{/}" if ticked else "[ ]") + " Back up first"), note),
             ("Uninstall", "")]
    items = [(strip(n) if i == sel else n, v) for i, (n, v) in enumerate(items)]
    body = [header("Uninstall"), ""] + menu(items, sel, 26) + ["", hint or "    {d}PostgreSQL stays installed; it may serve other programs.{/}"]
    return screen("limebox · Maintenance › Uninstall", body, checkbar())


def upd(ticked, note):
    maint1.UPD[0] = ((("{g}[x]{/}" if ticked else "[ ]") + " Back up first"), note)
    return maint1.update(0, checkbar(), HINT_ON if ticked else HINT_OFF)


HINT_ON = "    {d}Ticked because you backed up last time.{/}"
HINT_OFF = "    {d}Off unless you chose it last time.{/}"


print(page("Back up first: off by default, then remembered",
           "Reply: yes, or what to change.", [
    ("Update, the first time", "Off by default.", upd(False, "~/openvibes-0.2.9-2026-10-10-2041.dump")),
    ("Update, after backing up last time", "Ticked, because you chose it last time.",
     upd(True, "~/openvibes-0.2.9-2026-10-10-2041.dump")),
    ("Uninstall, the first time", "Off by default.", un(2, False, "~/openvibes-backup-2026-10-10-2104.dump", HINT_OFF)),
    ("Uninstall, after backing up last time", "Ticked, as last time.",
     un(2, True, "~/openvibes-backup-2026-10-10-2104.dump", HINT_ON)),
]))
