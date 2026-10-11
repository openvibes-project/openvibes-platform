import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import advanced as adv
from gen import bar, checkbar, header, menu, page, pad, screen  # noqa: E402

step = adv.step


def radio(items, chosen):
    return [(("(•) " if i == chosen else "( ) ") + n, v) for i, (n, v) in enumerate(items)]


AGENT = [("Your CA signs our request", "the key is made here, never leaves"),
         ("Import from your PKI", "certificate + key, or a .p12 file"),
         ("OpenVIBES makes its own CA", "for homelabs and tests")]
WEB = [("From the intermediate", "renewed automatically"),
       ("Your own certificate", "e.g. a wildcard; you renew it"),
       ("Automatic via ACME", "Let's Encrypt or your ACME server")]


def certstep(sel, agent=0, web=0, help_text="", b=None):
    items = [("{b}Agent certificates{/}", "")] + radio(AGENT, agent) + [("{b}Web address certificate{/}", "")] \
        + radio(WEB, web) + [("Next", "ports")]
    return step(2, items, sel, help_text, b or bar("{k} Space {/} Choose  {k} Enter {/} Confirm"),
                top=0 if sel < 5 else 4, shown=5, w=32)


ACME = [("ACME server", "https://ca.lime.lab/acme/acme/directory"),
        ("Account e-mail", "admin@lime.lab"),
        ("Challenge", "HTTP-01 on port 80 · or DNS-01"),
        ("Next", "ports")]

INFO = [("Agent certificates", "{g}renewed automatically{/} · intermediate from your PKI"),
        ("Intermediate", "Lime Lab Issuing CA 2 · until 2029-03-01"),
        ("Web address", "{g}ACME{/} · ca.lime.lab · renews in 52 days"),
        ("Names", "limebox.lan, openvibes.lime.lab")]
ACTS = [("Agent certificates", "change how they are issued"),
        ("Web address certificate", "change, or renew your own"),
        ("Names", "add or remove a name")]

print(page("Certificates for homelabs, companies and strict networks",
           "Two questions: who signs the agents' certificates, and where the web address's comes from. "
           "Reply per number: yes, or what to change.", [
    ("Install step 3: agent certificates", "Your CA signs our request is the default.",
     certstep(1, help_text="Your CA signs a request made here; the private key never leaves this host.")),
    ("↓ to Import from your PKI", "For PKIs that hand out a finished intermediate.",
     certstep(2, help_text="Paste or pick the certificate and its key, or a .p12 with its password.")),
    ("↓ to the web address: Automatic via ACME, Space", "Let's Encrypt for a public name, or step-ca, Vault, EJBCA inside.",
     certstep(7, web=2, help_text="Renewed automatically before it expires.")),
    ("Enter: the ACME details", "Only when ACME is chosen.",
     step(2, ACME, 0, "Your ACME directory URL; Let's Encrypt is filled in if you leave it empty.",
          bar("{k} Enter {/} Change"), w=24)),
    ("Later: Maintenance › Certificates", "Both parts, how each is issued, and how to change them.",
     screen("limebox · Maintenance › Certificates",
            [header("Certificates"), ""] + ["    " + pad(n, 24) + " " + v for n, v in INFO] + [""] + menu(ACTS, 0, 24),
            bar("{k} Enter {/} Open"))),
]))
