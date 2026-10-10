import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import ca2
from gen import bar, header, menu, page, pad, screen  # noqa: E402


def info(rows):
    return ["    " + pad(n, 26) + " " + v for n, v in rows]


OWN = [("Web and agents", "{g}renewed automatically{/} · next 2026-10-24"),
       ("Names", "limebox.lan, 192.168.1.10"),
       ("Intermediate", "signed by {b}Lime Lab Root CA{/} · until 2031-10-10")]
OURS = [("Web and agents", "{g}renewed automatically{/} · next 2026-10-24"),
        ("Names", "limebox.lan, 192.168.1.10"),
        ("Intermediate", "signed by the OpenVIBES root · until 2031-10-10"),
        ("Root key", "{d}offline: needed only to replace the intermediate{/}")]
ACTS_OWN = [("Names", "add or remove a name agents use"),
            ("Replace the intermediate", "a new request for your CA")]
ACTS_OURS = [("Names", "add or remove a name agents use"),
             ("Replace the intermediate", "needs the offline root key file")]


def certs(rows, acts, sel, b):
    body = [header("Certificates"), ""] + info(rows) + [""] + menu(acts, sel, 26)
    return screen("limebox · Maintenance › Certificates", body, b)


REPLACE = [("Show the request", "to copy it to your CA"),
           ("Signed certificate", "{y}not added yet{/}"),
           ("Your CA's certificate", "{g}✓{/} Lime Lab Root CA (kept)"),
           ("Replace", "once the signed certificate is added")]
replace = screen("limebox · Maintenance › Certificates › Replace", [header("Replace the intermediate"), "",
                 "    {d}The same steps as at install. Nothing changes until Replace.{/}", ""] + menu(REPLACE, 1, 26),
                 bar("{k} Enter {/} Add the signed certificate"))

print(page("Certificates: renewal is automatic; your CA is asked only for the intermediate",
           "Reply per number: yes, or what to change.", [
    ("Your own CA", "Renewals are automatic; Replace the intermediate is the install flow.",
     certs(OWN, ACTS_OWN, 1, bar("{k} Enter {/} Replace the intermediate"))),
    ("OpenVIBES made the CA", "The same screen; replacing needs the offline root key file.",
     certs(OURS, ACTS_OURS, 0, bar("{k} Enter {/} Names"))),
    ("Your own CA: Enter on Replace the intermediate", "Request, paste, checked at once, then Replace.", replace),
    ("Enter on Signed certificate, Paste it", "Exactly the install screen.", ca2.paste),
]))
