import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from gen import bar, header, menu, page, screen  # noqa: E402

gen.UPDATE = None
TOP = ["    {g}✓{/} Packages  {g}✓{/} PostgreSQL  {g}✓{/} Database  {y}■{/} {b}Certificate authority{/}", ""]
WAIT = [("Show the request", "to copy it to your CA"),
        ("Signed certificate", "{y}not added yet{/}"),
        ("Your CA's certificate", "{y}not added yet{/}"),
        ("Continue the install", "once both are added")]


def waiting(sel, items=WAIT, b=None):
    body = [header("Installing: sign the request with your CA")] + [""] + TOP + menu(items, sel, 26)
    return screen("limebox · Install", body, b or bar("{k} Enter {/} Open"))


request = screen("limebox · Install › Request", [
    header("The signing request"), "",
    "    {d}Select and copy it with your terminal; sign it as an intermediate{/}",
    "    {d}(CA:TRUE, pathlen 0). Also saved as ~/openvibes-intermediate.csr{/}", "",
    "    -----BEGIN CERTIFICATE REQUEST-----",
    "    MIIBmjCCAT8CAQAwTDELMAkGA1UEBhMCU0UxEDAOBgNVBAoMB2xpbWVsYWIxKzAp",
    "    BgNVBAMMIk9wZW5WSUJFUyBpbnRlcm1lZGlhdGUgKGxpbWVib3gubGFuKTBZMBMG",
    "    {d}… 5 more lines{/}",
    "    -----END CERTIFICATE REQUEST-----",
], bar("{k} ⭡⭣ {/} Scroll", nav=False))

HOW = [("Paste it", "paste the PEM text into this terminal"),
       ("From a file on this host", "copied here with scp or a USB stick")]
how = screen("limebox · Install › Signed certificate", [header("Add the signed certificate"), ""] + menu(HOW, 0, 26),
             bar("{k} Enter {/} Paste it"))

paste = screen("limebox · Install › Signed certificate", [
    header("Paste the signed certificate"), "",
    "    {d}Paste the whole block, BEGIN to END lines included.{/}", "",
    "  {d}┌{/}" + "{d}─{/}" * 70 + "{d}┐{/}",
    "  {d}│{/} -----BEGIN CERTIFICATE-----" + " " * 41 + " {d}│{/}",
    "  {d}│{/} MIICFzCCAb2gAwIBAgIUQ0q3xV8c2rS9uY1mJ6l5aT0wCgYIKoZIzj0EAwIw" + " " * 8 + " {d}│{/}",
    "  {d}│{/} … " + " " * 66 + " {d}│{/}",
    "  {d}│{/} -----END CERTIFICATE-----█" + " " * 42 + " {d}│{/}",
    "  {d}└{/}" + "{d}─{/}" * 70 + "{d}┘{/}", "",
    "    {g}✓{/} Intermediate for limebox.lan · signed by Lime Lab Root CA",
    "    {g}✓{/} Matches the request · valid until 2031-10-10",
], bar("{k} Enter {/} Use it", "{k} Esc {/} Cancel", nav=False))

done = waiting(3, [("Show the request", "to copy it to your CA"),
                   ("Signed certificate", "{g}✓ added{/} · signed by Lime Lab Root CA"),
                   ("Your CA's certificate", "{g}✓ added{/} · Lime Lab Root CA"),
                   ("Continue the install", "both are added")], bar("{k} Enter {/} Continue the install"))

print(page("Your own CA: getting the request out and the certificates in",
           "Paste or pick a file, checked on the spot. Reply per number: yes, or what to change.", [
    ("The install waits at the CA step", "Show the request first; two certificates to add.", waiting(0)),
    ("Enter on Show the request", "Plain text to copy with your terminal; also saved as a file.", request),
    ("Enter on Signed certificate", "Two ways to add it.", how),
    ("Enter on Paste it", "Paste the block; it is checked at once, before you use it.", paste),
    ("Both added", "Continue goes on with the install.", done),
]))
