import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import advanced as adv
    import ca
    import ca2
    import install
import gen  # noqa: E402
from gen import bar, header, page, screen  # noqa: E402

gen.UPDATE = None
step = adv.step

PORTS = [("Console", "{y}443 is in use by nginx{/} · 8443 proposed"), ("Agent connections", "18423"),
         ("Rule distribution", "18424"), ("Network devices", "514/udp · open it in your firewall"),
         ("Next", "review")]
PORTS_OK = [("Console", "8443"), ("Agent connections", "18423"), ("Rule distribution", "18424"),
            ("Network devices", "514/udp · open it in your firewall"), ("Next", "review")]
REVIEW = [("Optional", "agent on this host · no assistant"), ("Names", "limebox.lan, 192.168.1.10"),
          ("Certificates", "your own CA · {g}✓ signed by Lime Lab Root CA{/}"),
          ("Ports", "8443, 18423, 18424, 514/udp"), ("Install", "asks for your password once")]

finished = screen("limebox · Install", [
    header("OpenVIBES is installed"), "",
    "    Open the console    {b}https://limebox.lan:8443{/}",
    "    Sign in as          {b}admin{/}",
    "    Password            {b}Kq7-vR2p-Xw9m{/}   {y}shown only now: write it down{/}", "",
    "    Certificates        {b}signed by Lime Lab Root CA{/}",
    "                        {d}browsers that trust your CA show no warning{/}", "",
    "    {d}Next: sign in, change the password, then add hosts under Agents.{/}",
], bar("{k} Enter {/} Continue to Home", "", nav=False))

CA_ROWS = [("Show the request", "to copy it to your CA"),
           ("Signed certificate", "{y}not added yet{/}"),
           ("Your CA's certificate", "{y}not added yet{/}"),
           ("Next", "once both are added")]
CA_DONE = [("Show the request", "to copy it to your CA"),
           ("Signed certificate", "{g}✓ added{/} · signed by Lime Lab Root CA"),
           ("Your CA's certificate", "{g}✓ added{/} · Lime Lab Root CA"),
           ("Next", "ports")]


def ca_step(rows, sel, b):
    return step(2, rows, sel, "OpenVIBES made a request; your CA signs it as an intermediate.", b, w=24)


def in_step(title, body, b):
    return screen(f"limebox · Install › Certificates › {title}", body, b)


flow = [
    ("Start: Welcome", "A host without OpenVIBES. Choose what to install is highlighted.", install.welcome(0)),
    ("Enter: step 1 of 5, Optional", "Agent on this host is ticked; the core is always installed.", adv.comp(0)),
    ("↓ twice to Next, Enter: step 2, Names", "Host name filled in from this host.",
     step(1, adv.NAMES, 0, "The name agents and your browser use to reach this host.", bar("{k} Enter {/} Change"))),
    ("↓ to Other names, Enter, type, Enter", "Edited in place.",
     step(1, [("Host name", "limebox.lan"), ("Other names", "192.168.1.10█"), ("Next", "certificates")], 1,
          "Other names or addresses agents may use, comma-separated.",
          bar("{b}Other names:{/} type  {k} Enter {/} Done", "{k} Esc {/} Cancel", nav=False))),
    ("↓ to Next, Enter: step 3, Certificates", "Your own CA is the default.", ca.certs(0)),
    ("Space keeps your own CA, ↓ to Next, Enter", "OpenVIBES makes the request now; nothing is installed yet.",
     ca_step(CA_ROWS, 0, bar("{k} Enter {/} Show the request"))),
    ("Enter: the request", "Copy it with your terminal, sign it with your CA.",
     ca2.request),
    ("Esc, ↓, Enter on Signed certificate, Paste it", "Pasted and checked at once.", ca2.paste),
    ("Both added", "Next goes on to the ports.", ca_step(CA_DONE, 3, bar("{k} Enter {/} Next"))),
    ("Enter: step 4, Ports", "443 is taken on this host: flagged, with a free port proposed.",
     step(3, PORTS, 0, "Enter to keep 8443 or type another port.", bar("{k} Enter {/} Change"))),
    ("Enter: 8443 accepted", "Nothing is flagged any more.",
     step(3, PORTS_OK, 4, "Go on to the review.", bar("{k} Enter {/} Next"))),
    ("Enter: step 5, Review", "Every choice, certificates ready; Enter on a line jumps back to its step.",
     step(4, REVIEW, 4, "Starts the install; it asks for your password once.", bar("{k} Enter {/} Install"))),
    ("Enter on Install: your password", "Asked once, in the bar; never stored.",
     step(4, REVIEW, 4, "Starts the install; it asks for your password once.",
          bar("{b}Your password (sudo):{/} ••••••••█  {k} Enter {/} Install", "{k} Esc {/} Back", nav=False))),
    ("Installing", "From start to finish, no pauses.", install.progress(1, "setting up the database server")),
    ("Later in the install", "Done steps get a ✓.", install.progress(6, "starting the services")),
    ("Finished", "Labelled; the password shown once.", finished),
]
print(page("Choose what to install: the whole flow, key by key",
           "From a fresh host to a finished install with your own CA; the certificates are done before Install. Reply per number: yes, or what to change.",
           flow))
