import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import full_advanced
    import home3
    import maint1
import gen  # noqa: E402
from gen import ask, bar, checkbar, header, menu, page, screen  # noqa: E402

# ---- Update OpenVIBES, from Home and back ----
gen.UPDATE = "0.2.9"


def upd(rows, sel, b, hint=None):
    maint1.UPD[:] = rows
    return maint1.update(sel, b, ("    {d}" + hint + "{/}") if hint else None)


R0 = [("[ ] Back up first", "{d}no folder chosen yet{/}"), ("Update now", "about 3 minutes"),
      ("What's new", "the release notes")]
R1 = [("{g}[x]{/} Back up first", ""), ("Save in folder", "{y}choose a folder{/}"), ("Update now", "about 3 minutes")]
R2 = [("{g}[x]{/} Back up first", ""), ("Save in folder", "/mnt/nas/openvibes█"), ("Update now", "about 3 minutes")]
R3 = [("{g}[x]{/} Back up first", ""), ("Save in folder", "/mnt/nas/openvibes"), ("Update now", "about 3 minutes")]

update_flow = [
    ("Home: 0.2.9 is available", "The version line says so on every screen.", home3.home(0)),
    ("⭣ once", "Maintenance highlighted.", home3.home(1)),
    ("Enter: Maintenance", "Update OpenVIBES is first.", home3.maint(0, 0)),
    ("Enter: Update OpenVIBES", "First time: no backup folder chosen.",
     upd(R0, 0, checkbar(), "Off unless you chose it last time.")),
    ("Space: tick Back up first", "A folder line appears.", upd(R1, 1, bar("{k} Enter {/} Choose a folder"),
                                                              "A NAS mount, a backup disk: any folder this host can write.")),
    ("Enter, type the folder", "Checked as you type.",
     upd(R2, 1, bar("{b}Folder:{/} type, or {k} Tab {/} to browse  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False),
         "/mnt/nas/openvibes exists and is writable · 1.8 TB free.")),
    ("Enter, then ⭣ to Update now", "Ready.", upd(R3, 2, bar("{k} Enter {/} Update now"))),
    ("Enter: the question", "Yes is highlighted; Enter confirms.", upd(R3, 2, ask("Update to 0.2.9?", "about 3 min"))),
    ("Enter: updating", "Back up first, then the rest.", maint1.uprog(0, "writing /mnt/nas/openvibes/openvibes-0.2.9-…")),
    ("Later in the update", "", maint1.uprog(2, "12 of 17 packages")),
    ("Done", "One clear result.", maint1.uprog(0, "", finished=True)),
]
gen.UPDATE = None
after = home3.home(0)
gen.VERSION = "v0.2.9"
update_flow.append(("Enter, Esc: back on Home", "v0.2.9, no update notice any more.", home3.home(0)))
gen.VERSION = "v0.2.8"

# ---- Install (advanced), fresh host to Finished ----
install_flow = full_advanced.flow

out = page("1. Update OpenVIBES: the whole flow, key by key",
           "From Home with an update available, back to Home on the new version.", update_flow)
out += page("2. Install: the whole flow, key by key",
            "From a fresh host to a finished install with your own CA.", install_flow)
print(out)
