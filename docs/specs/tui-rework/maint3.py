import sys

sys.path.insert(0, sys.argv[1])
from gen import ask, bar, header, menu, page, pad, screen  # noqa: E402


def info(rows):
    # Same value column as the entries below (name width 26).
    return ["    " + pad(n, 26) + " " + v for n, v in rows]


CERT_INFO = [("Web and agents", "{y}expires in 21 days{/} (2026-10-31)"),
             ("Names", "limebox.lan, 192.168.1.10"),
             ("Signed by", "OpenVIBES intermediate · until 2031"),
             ("Intermediate", "signed by Lime Lab Root CA")]
CERT_ACTS = [("Renew now", "a new certificate for two years"),
             ("Names", "add or remove a name agents use"),
             ("Replace the intermediate", "a new request for your CA")]


def certs(sel, b):
    body = [header("Certificates"), ""] + info(CERT_INFO) + [""] + menu(CERT_ACTS, sel, 26)
    return screen("limebox · Maintenance › Certificates", body, b)


DB_INFO = [("Schema", "46 · up to date"), ("Size", "3.1 GB on a 120 GB disk (41% used)"),
           ("Data kept", "90 days (set in the console)"),
           ("Clean-up", "{g}automatic{/}, nightly at 03:00 · ran today"),
           ("Removed last night", "0.4 GB older than 90 days")]


def db(b):
    body = [header("Database"), ""] + info(DB_INFO)
    return screen("limebox · Maintenance › Database", body, b)


SIGN = [("Reset the admin password", "a new password, shown once")]


def signin(b, shown=False):
    body = [header("Console sign-in"), "",
            "    {d}For when nobody can sign in to the console any more.{/}", ""]
    if shown:
        body += info([("Sign in as", "{b}admin{/}"), ("New password", "{b}Tz4-mW8q-Hn2c{/}  {y}shown only now{/}")])
        body += ["", "    {d}You are asked to change it at the next sign-in.{/}"]
    else:
        body += menu(SIGN, 0, 26)
    return screen("limebox · Maintenance › Console sign-in", body, b)


print(page("Maintenance: Certificates, Database and Console sign-in",
           "Key by key. Reply per number: yes, or what to change.", [
    ("Maintenance › Certificates", "What the certificates are, then what you can do.",
     certs(0, bar("{k} Enter {/} Renew now"))),
    ("Enter on Renew now", "", certs(0, ask("Renew the certificate?", "no downtime"))),
    ("Done", "", certs(0, bar("{g}✓{/} Renewed · valid until 2028-10-10"))),
    ("Maintenance › Database", "A report only: clean-up is automatic; Back up is its own entry.",
     db(bar("", "{k} Esc {/} Back  {k} ? {/}", nav=False))),
    ("Maintenance › Console sign-in", "", signin(bar("{k} Enter {/} Reset the admin password"))),
    ("Enter, Yes: the new password", "Shown once, labelled.", signin(bar("{k} Enter {/} Done", "", nav=False), shown=True)),
]))
