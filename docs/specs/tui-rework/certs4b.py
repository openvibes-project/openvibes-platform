import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import advanced as adv
    import certs2
from gen import bar, header, menu, page, screen  # noqa: E402

# Sub-project 4b: Import from your PKI. The third choice in Install step 3
# (certs3.py), what is added and how it is checked, and Maintenance ›
# Certificates › Replace for an imported intermediate.
HELP = "Paste or pick the certificate and its key, or a .p12 with its password."
CHOICES = [("( ) Your own CA", "your CA signs an intermediate for OpenVIBES"),
           ("(•) Import from your PKI", "a finished intermediate and its key"),
           ("( ) OpenVIBES makes one", "a new root CA; its key goes offline after")]
NONE = [("Certificate", "{y}not added yet{/}"), ("Private key", "{y}not added yet{/}"),
        ("Next", "once both are added")]
BOTH = [("Certificate", "{g}✓ added{/}{d} · Lime Lab OpenVIBES CA{/}"),
        ("Private key", "{g}✓ added{/}{d} · matches the certificate{/}"),
        ("Next", "ports")]


def certstep(rows, sel, help_text, b, top=0):
    return adv.step(2, CHOICES + rows, sel, help_text, b, top=top, shown=5, w=26)


def box(lines):
    return (["  {d}┌{/}" + "{d}─{/}" * 70 + "{d}┐{/}"]
            + ["  {d}│{/} " + line + " " * (68 - len(line)) + " {d}│{/}" for line in lines]
            + ["  {d}└{/}" + "{d}─{/}" * 70 + "{d}┘{/}", ""])


HOW = [("Paste it", "PEM text: ours first, then the CAs above it"),
       ("From a file on this host", "a .pem, or a .p12 / .pfx with the key in it")]
how = screen("limebox · Install › Certificate", [header("Add the certificate"), ""] + menu(HOW, 0, 26),
             bar("{k} Enter {/} Paste it"))

pasted = screen("limebox · Install › Certificate", [
    header("Paste the certificate"), "",
    "    {d}Our intermediate first, then each CA above it. The root may be left out.{/}", ""]
    + box(["-----BEGIN CERTIFICATE-----", "MIIFbTCCA1WgAwIBAgIUM2x0Q2c9V7kZpR1hX0b8yA3eM4owDQYJKoZIhvcNAQEL",
           "…", "-----END CERTIFICATE-----"]) + [
    "    {g}✓{/} Lime Lab OpenVIBES CA · may sign certificates · valid until 2029-03-01",
    "    {g}✓{/} Chain: Lime Lab Issuing CA › Lime Lab Root CA (root, also added)",
], bar("{k} Enter {/} Use it", "{k} Esc {/} Cancel", nav=False))

short = screen("limebox · Install › Certificate", [
    header("Paste the certificate"), "",
    "    {d}Our intermediate first, then each CA above it. The root may be left out.{/}", ""]
    + box(["-----BEGIN CERTIFICATE-----", "MIIFbTCCA1WgAwIBAgIUM2x0Q2c9V7kZpR1hX0b8yA3eM4owDQYJKoZIhvcNAQEL",
           "…", "-----END CERTIFICATE-----"]) + [
    "    {g}✓{/} Lime Lab OpenVIBES CA · may sign certificates · valid until 2029-03-01",
    "    {r}✗ Signed by Lime Lab Issuing CA, missing here: paste it below this one.{/}",
], bar("", "{k} Esc {/} Cancel", nav=False))

p12 = screen("limebox · Install › Certificate", [
    header("Add the certificate"), "", ] + menu(HOW, 1, 26) + [
    "", "    {g}✓{/} /media/usb/openvibes.pfx · a .p12 file: it is locked with a password",
], bar("{b}Its password:{/} ••••••••••█  {k} Enter {/} Open it", "{k} Esc {/} Cancel", nav=False))

p12_done = certstep(BOTH, 5,
                    "From /media/usb/openvibes.pfx. Delete that file now: its key is kept here.",
                    bar("{k} Enter {/} Next"), top=1)

KEYHOW = [("Paste it", "the PEM text of the key"),
          ("From a file on this host", "a .pem or .key file")]
key = screen("limebox · Install › Private key", [
    header("Paste the private key"), "",
    "    {d}It stays on this host, readable by root only.{/}", ""]
    + box(["-----BEGIN ENCRYPTED PRIVATE KEY-----", "MIIFLTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQIq3x0Pz8kq2ACAggA",
           "…", "-----END ENCRYPTED PRIVATE KEY-----"]) + [
    "    {g}✓{/} An RSA key (3072 bits), locked with a password",
], bar("{b}Its password:{/} ••••••••••█  {k} Enter {/} Unlock", "{k} Esc {/} Cancel", nav=False))

wrongkey = screen("limebox · Install › Private key", [
    header("Paste the private key"), "",
    "    {d}It stays on this host, readable by root only.{/}", ""]
    + box(["-----BEGIN EC PRIVATE KEY-----", "MHcCAQEEIBq0m7S3k8Yx1p0VZ2u9c3Jx5n2dL8y1wQ4r6t9eYk0aoAoGCCqGSM49",
           "…", "-----END EC PRIVATE KEY-----"]) + [
    "    {r}✗ Not the key of Lime Lab OpenVIBES CA: paste the key it was made with.{/}",
], bar("", "{k} Esc {/} Cancel", nav=False))

REFUSED = [
    "{r}✗ Lime Lab Web is not a CA, so it cannot sign agent certificates.{/}",
    "{r}✗ Lime Lab Issuing CA allows no CA below it: ask for one more level.{/}",
    "{r}✗ Valid until 2026-12-01: under the 90 days a server certificate lasts.{/}",
    "{r}✗ A 1024-bit RSA key is too weak: 2048 bits or more.{/}",
    "{r}✗ Wrong password for /media/usb/openvibes.pfx.{/}",
    "{r}✗ Replace: under Other Root CA, not Lime Lab Root CA, so agents would stop{/}",
    "{r}  trusting this host. Ask for one under the same root.{/}",
]
refused = screen("limebox · Install › Certificate", [
    header("What is refused, and the line that says so"), ""] + ["    " + r for r in REFUSED],
    bar("", "{k} Esc {/} Back", nav=False))

INFO = [("Web and agents", "{g}renewed automatically{/} · next 2026-12-24"),
        ("Names", "limebox.lan, 192.168.1.10"),
        ("Intermediate", "from your PKI · until 2029-03-01"),
        ("Signed by", "Lime Lab Issuing CA › {b}Lime Lab Root CA{/}")]
ACTS = [("Names", "add or remove a name agents use"),
        ("Replace the intermediate", "import the next one from your PKI")]
REPL = [("Certificate", "{g}✓ added{/}{d} · Lime Lab OpenVIBES CA 2{/}"),
        ("Private key", "{g}✓ added{/}{d} · matches the certificate{/}"),
        ("Replace", "agents move over in 30 days")]
replace = screen("limebox · Maintenance › Certificates › Replace", [
    header("Replace the intermediate"), "",
    "    {d}The same screens as at install. Nothing changes until Replace.{/}", ""] + menu(REPL, 2, 26) + [
    "", "    {g}✓{/} Under the same root: agents keep working."],
    bar("{k} Enter {/} Replace"))

print(page("Certificates 4b: importing a finished intermediate from your PKI",
           "Install step 3, then Maintenance › Certificates. Reply per number: yes, or what to change.", [
    ("Step 3, ↓ to Import from your PKI, Space", "The third choice from certs3.py; two rows to fill, like Your own CA.",
     certstep(NONE, 1, HELP, bar("{k} Space {/} Choose"))),
    ("↓ to Certificate, Enter", "Paste it, or a file: a .p12 / .pfx brings the key with it.", how),
    ("Paste it", "Checked at once: what it is, that it may sign, how long, and the chain up to the root.", pasted),
    ("A chain with a gap", "Says which CA is missing and where to put it; Use it does nothing.", short),
    ("Or From a file: a .pfx", "After the file browser, the password is asked in the bar.", p12),
    ("The .pfx opened", "Both rows are filled from it; the help line says to delete the file.", p12_done),
    ("Or PEM: the private key, locked", "A locked key asks for its password; an open one needs none.", key),
    ("A key for another certificate", "Checked against the certificate already added.", wrongkey),
    ("Everything else refused", "One red line each, saying what to ask the PKI for.", refused),
    ("Later: Maintenance › Certificates", "Where the intermediate came from, and which root agents trust.",
     certs2.certs(INFO, ACTS, 1, bar("{k} Enter {/} Replace the intermediate"))),
    ("Replace the intermediate", "Import the next one with the same rows; then the 4a question and steps.", replace),
]))
