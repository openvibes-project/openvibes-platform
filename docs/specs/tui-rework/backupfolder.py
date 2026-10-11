import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import maint1
from gen import bar, checkbar, header, menu, page, screen  # noqa: E402


def upd(rows, sel, b, hint):
    maint1.UPD[:] = rows
    return maint1.update(sel, b, "    {d}" + hint + "{/}")


FIRST = [("[ ] Back up first", "{d}no folder chosen yet{/}"), ("Update now", "about 3 minutes"),
         ("What's new", "the release notes")]
TICKED = [("{g}[x]{/} Back up first", ""), ("Save in folder", "{y}choose a folder{/}"),
          ("Update now", "about 3 minutes")]
PICKING = [("{g}[x]{/} Back up first", ""), ("Save in folder", "/mnt/nas/openvibes█"),
           ("Update now", "about 3 minutes")]
LATER = [("{g}[x]{/} Back up first", "/mnt/nas/openvibes"), ("Update now", "about 3 minutes"),
         ("What's new", "the release notes")]

print(page("Back up first: you choose the folder; it is remembered",
           "No default path until you have chosen one. Reply: yes, or what to change.", [
    ("Update, the first time", "No folder shown: OpenVIBES does not guess where your backups go.",
     upd(FIRST, 0, checkbar(), "Off unless you chose it last time.")),
    ("Space: tick it", "A folder line appears; it has to be filled in before Update now.",
     upd(TICKED, 1, bar("{k} Enter {/} Choose a folder"), "A NAS mount, a backup disk: any folder this host can write.")),
    ("Enter: type or browse", "Checked as you type: the folder exists and is writable.",
     upd(PICKING, 1, bar("{b}Folder:{/} type, or {k} Tab {/} to browse  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False),
         "/mnt/nas/openvibes exists and is writable · 1.8 TB free.")),
    ("The next update", "Your folder is remembered; each backup gets its own file name in it.",
     upd(LATER, 0, checkbar(), "Ticked because you backed up last time · a new file each time.")),
]))
