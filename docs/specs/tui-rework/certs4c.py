import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import certs2
    import certs4b
    import maint2b
from gen import ask, bar, header, menu, page, screen  # noqa: E402

# Sub-project 4c: the console's own certificate, as other self-hosted tools
# do it. Install asks nothing; Maintenance › Certificates shows the
# console's certificate and offers one action. The add screens are 4b's.
WHERE = "limebox · Maintenance › Certificates"
OURS = [("Agents", "{g}renewed automatically{/} · next 2026-12-24"),
        ("Console", "{g}from the platform{/} · renewed with the agents"),
        ("Names", "limebox.lan, 192.168.1.10"),
        ("Intermediate", "signed by the OpenVIBES root · until 2028-10-24")]
OWN = [("Agents", "{g}renewed automatically{/} · next 2026-12-24"),
       ("Console", "{b}your own{/} · *.limebox.se · until 2027-03-01"),
       ("Names", "limebox.lan, openvibes.limebox.se, 192.168.1.10"),
       ("Intermediate", "signed by the OpenVIBES root · until 2028-10-24")]
SOON = OWN[:1] + [("Console", "{y}your own · ends 2026-11-15, in 21 days{/}")] + OWN[2:]
ACTS = [("Names", "add or remove a name agents use"),
        ("Replace the intermediate", "needs the offline root key file"),
        ("Console certificate", "use your own")]
ACTS_OWN = ACTS[:2] + [("Console certificate", "use a new one, or go back to the platform's")]


def certs(rows, acts, sel, b):
    return screen(WHERE, [header("Certificates"), ""] + certs2.info(rows) + [""] + menu(acts, sel, 26), b)


USE = "limebox · Maintenance › Certificates › Console"
NOTE = "    {d}For the console in the browser only; agents keep the platform's.{/}"


def use(rows, sel, b, lines=()):
    body = [header("Use your own certificate"), "", NOTE, ""] + menu(rows, sel, 26)
    return screen(USE, body + ([""] + ["    " + x for x in lines] if lines else []), b)


EMPTY = [("Certificate", "{y}not added yet{/}"), ("Private key", "{y}not added yet{/}"),
         ("Use it", "once both are added")]
BOTH = [("Certificate", "{g}✓ added{/}{d} · *.limebox.se{/}"),
        ("Private key", "{g}✓ added{/}{d} · matches the certificate{/}"),
        ("Use it", "the console restarts")]
COVERS = "{g}✓{/} Covers openvibes.limebox.se, one of this console's names."

pasted = screen(USE + " › Certificate", [
    header("Paste the certificate"), "",
    "    {d}The console's certificate first, then the CAs above it.{/}", ""]
    + certs4b.box(["-----BEGIN CERTIFICATE-----", "MIIFdzCCBF+gAwIBAgISBN3fN8b2LH9vJm0QVJ7xJm6kMA0GCSqGSIb3DQEBCwUA",
                   "…", "-----END CERTIFICATE-----"]) + [
    "    {g}✓{/} *.limebox.se · for server use · valid until 2027-03-01",
    "    " + COVERS,
], bar("{k} Enter {/} Use it", "{k} Esc {/} Cancel", nav=False))

none = screen(USE + " › Certificate", [
    header("Paste the certificate"), "",
    "    {d}The console's certificate first, then the CAs above it.{/}", ""]
    + certs4b.box(["-----BEGIN CERTIFICATE-----", "MIIFdzCCBF+gAwIBAgISBN3fN8b2LH9vJm0QVJ7xJm6kMA0GCSqGSIb3DQEBCwUA",
                   "…", "-----END CERTIFICATE-----"]) + [
    "    {g}✓{/} *.limebox.se · for server use · valid until 2027-03-01",
    "    {r}✗ Covers none of this console's names: add one under Names first.{/}",
], bar("", "{k} Esc {/} Cancel", nav=False))

REFUSED = [
    "{r}✗ This is a CA certificate: pick the console's own certificate.{/}",
    "{r}✗ Not for servers (its extended key usage): ask for a server certificate.{/}",
    "{r}✗ Expired on 2026-09-30: ask for a new one.{/}",
    "{r}✗ Valid from 2026-11-01: not valid yet.{/}",
    "{r}✗ Not the key of *.limebox.se: paste the key it was made with.{/}",
]
refused = screen(USE + " › Certificate", [header("What is refused, and the line that says so"), ""]
                 + ["    " + r for r in REFUSED], bar("", "{k} Esc {/} Back", nav=False))

DONE = "The console uses your certificate · until 2027-03-01 (2 s)"
GONE = [("Use a new one", "paste or pick, as before"),
        ("Go back to the platform's", "renewed automatically with the agents")]

print(page("Certificates 4c: the console's own certificate",
           "As other self-hosted tools do it: nothing at install, one action later. "
           "Reply per number: yes, or what to change.", [
    ("Maintenance › Certificates, out of the box", "The console's row is new; it comes from the platform.",
     certs(OURS, ACTS, 2, bar("{k} Enter {/} Console certificate"))),
    ("Enter: Use your own certificate", "The same rows as 4b's import: paste or pick, or a .p12 with its password.",
     use(EMPTY, 0, bar("{k} Enter {/} Open"))),
    ("Paste it", "Checked at once, and which of the console's names it covers.", pasted),
    ("A certificate for no name of this console", "Says what to do; Use it does nothing.", none),
    ("Everything else refused", "One red line each.", refused),
    ("Both added", "Use it: the console restarts with it.", use(BOTH, 2, bar("{k} Enter {/} Use it"))),
    ("Enter: the question", "As every other question.", use(BOTH, 2, ask("Use it?", "the console restarts"))),
    ("Yes: your password, then one result line", "As Update and Repair.",
     use(BOTH, 2, bar("{g}✓{/} " + DONE, nav=False))),
    ("Back on Certificates", "Your own is named; Names shows the name it covers.",
     certs(OWN, ACTS_OWN, 2, bar("{k} Enter {/} Console certificate"))),
    ("Enter on Console certificate, once yours is in", "Use a new one, or go back.",
     screen(USE, [header("The console's certificate"), "", "    {d}Yours: *.limebox.se, until 2027-03-01.{/}", ""]
            + menu(GONE, 1, 26), bar("{k} Enter {/} Go back"))),
    ("Go back: the question, then the result", "The platform's certificate is issued again for the names.",
     screen(USE, [header("The console's certificate"), "", "    {d}Yours: *.limebox.se, until 2027-03-01.{/}", ""]
            + menu(GONE, 1, 26), ask("Go back?", "the console restarts"))),
    ("Status, 30 days before yours ends", "Amber in Status and on Home; red once it has ended.",
     screen("limebox · Status", [header("Status"), "",
                                 "    {y}▲{/} Console certificate: yours ends 2026-11-15, in 21 days",
                                 "", "    {d}Use a new one in Maintenance › Certificates.{/}"],
            bar("{k} Enter {/} Open"))),
    ("…and Certificates then", "The row turns amber with the days left.",
     certs(SOON, ACTS_OWN, 2, bar("{k} Enter {/} Console certificate"))),
]))
