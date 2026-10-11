import sys

sys.path.insert(0, sys.argv[1])
import gen  # noqa: E402
from advanced import step  # noqa: E402
from gen import bar, header, menu, page, screen  # noqa: E402

gen.UPDATE = None
CERTS = [("(•) Your own CA", "your CA signs an intermediate for OpenVIBES"),
         ("( ) OpenVIBES makes one", "a new root CA; its key goes offline after"),
         ("Next", "ports")]
HELP = {0: "For networks with their own PKI. Your root key never comes near this host.",
        1: "For networks without a CA of their own.",
        2: "Go on to the ports."}


def certs(sel):
    b = bar("{k} Space {/} Choose") if sel < 2 else bar("{k} Enter {/} Next")
    return step(2, CERTS, sel, HELP[sel], b, w=24)


WAIT = [("Import the signed certificate", "~/openvibes-intermediate.crt"),
        ("Your CA's certificate", "~/company-root-ca.crt"),
        ("Continue the install", "once both files are in place")]


def waiting(sel):
    body = [header("Installing: sign the request with your CA"), "",
            "    {g}✓{/} Packages  {g}✓{/} PostgreSQL  {g}✓{/} Database  {y}■{/} {b}Certificate authority{/}", "",
            "    OpenVIBES made a signing request for its intermediate:",
            "    {b}/home/lime/openvibes-intermediate.csr{/}",
            "    {d}Sign it with your CA as an intermediate (CA:TRUE, pathlen 0).{/}", ""] + menu(WAIT, sel, 30)
    return screen("limebox · Install", body, bar("{k} Enter {/} " + ("Change" if sel < 2 else "Continue")))


print(page("Certificates: your own CA first",
           "Step 3 now defaults to your organisation's CA. The install pauses at the CA step until the "
           "signed intermediate is back. Reply per number: yes, or what to change.", [
    ("Step 3: Certificates", "Your own CA is the default.", certs(0)),
    ("↓ once: OpenVIBES makes one", "For networks without their own CA.", certs(1)),
    ("During the install: the request is ready", "The install waits here; you sign the request elsewhere.",
     waiting(0)),
    ("↓ to Continue", "Enter checks both files and goes on.", waiting(2)),
]))
