import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import bar, header, pad, page, screen  # noqa: E402

gen.UPDATE = None
ROWS = [("Host name", "limebox.lan", "The name agents and your browser use to reach this host."),
        ("Other names", "192.168.1.10", "Other names or addresses agents may use, comma-separated."),
        ("Root key file", "~/openvibes-root-ca.key", "The CA's root key: written once here, move it offline."),
        ("{g}[x]{/} Agent on this host", "watch this host too", "Untick only if this server must not run an agent."),
        ("Install", "everything else uses the defaults", "Starts the install; it asks for your password once.")]


def quick(sel, editing=None):
    body = [header("Quick install: only what OpenVIBES cannot know"), ""]
    for i, (name, val, _) in enumerate(ROWS):
        shown = val + ("█" if editing == i else "")
        if i == sel:
            plain = name.replace("{g}", "").replace("{/}", "")
            body.append(f"  {{s}}▸ {pad(plain, 22)} {pad(shown, 47)}{{/}}")
        else:
            body.append(f"    {pad(name, 22)} {{d}}{shown}{{/}}")
        body.append("")
    body[-1] = "    {d}" + ROWS[sel][2] + "{/}"
    return screen("limebox · Install › Quick install", body,
                  bar("{k} Space {/} Select" if sel == 3 else "{k} Enter {/} " + ("Install" if sel == 4 else "Change")))


print(page("Quick install: the settings only you know",
           "Enter on Quick install opens this short list; everything else uses the defaults. "
           "Reply: yes, or what to add or remove.", [
    ("Enter on Quick install", "Highlight on the host name, filled in from this host.", quick(0)),
    ("↓ once: Other names", "For example the IP address, if agents use it.", quick(1)),
    ("↓ to Agent on this host", "Ticked by default; Space unticks it.", quick(3)),
    ("↓ to Install", "Enter asks for your password, then installs.", quick(4)),
]))
