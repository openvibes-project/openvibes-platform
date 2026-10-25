import contextlib
import io
import sys

sys.path.insert(0, sys.argv[1])
with contextlib.redirect_stdout(io.StringIO()):
    import certs2
    import maint2b
from gen import ask, bar, header, menu, page, screen  # noqa: E402

# Sub-project 4a: what certs2.py did not show. Replacing the intermediate
# when OpenVIBES made the CA (the offline root key file), the question,
# the run and the page afterwards (both CA kinds end the same way).
WHERE = "limebox · Maintenance › Certificates › Replace"
NOTE = "    {d}Needs the root key kept offline at install. Nothing changes until Replace.{/}"
PW = maint2b.PW


def replace(rows, sel, b, line=""):
    body = [header("Replace the intermediate"), "", NOTE, ""] + menu(rows, sel, 26)
    if line:
        body += ["", "    " + line]
    return screen(WHERE, body, b)


EMPTY = [("Root key file", "{y}not added yet{/}"),
         ("Replace", "once the root key file is added")]
WRONG = [("Root key file", "{r}✗{/} /media/usb/other.key")]
WRONG += EMPTY[1:]
RIGHT = [("Root key file", "{g}✓{/} /media/usb/openvibes-root.key"),
         ("Replace", "a new intermediate, signed here")]
STEPS = ["Making the new intermediate", "Trusting the old and the new one",
         "Issuing the server certificates", "Restarting the services"]
AFTER = [("Web and agents", "{g}renewed automatically{/} · next 2026-12-24"),
         ("Names", "limebox.lan, 192.168.1.10"),
         ("Intermediate", "signed by the OpenVIBES root · until 2028-10-24"),
         ("Previous intermediate", "{d}trusted until 2026-11-24, as agents move over{/}"),
         ("Root key", "{d}offline: needed only to replace the intermediate{/}")]
DONE = "Replaced · agents move over in 30 days · put the key offline again (11 s)"

print(page("Certificates 4a: replacing the intermediate when OpenVIBES made the CA",
           "Key by key from Maintenance › Certificates. Reply per number: yes, or what to change.", [
    ("Maintenance › Certificates, ⭣ to Replace the intermediate", "As approved (certs2.py).",
     certs2.certs(certs2.OURS, certs2.ACTS_OURS, 1, bar("{k} Enter {/} Replace the intermediate"))),
    ("Enter: Replace", "Only the root key file is asked: this host makes and signs the new intermediate.",
     replace(EMPTY, 0, bar("{k} Enter {/} Pick the file"))),
    ("Enter: the file browser", "The same browser as the install's Root key file, arrows and Enter.",
     replace(EMPTY, 0, bar("{k} Enter {/} Pick the file"), "{d}(the install's file browser opens here){/}")),
    ("A key that is not this root's", "Checked at once, in red; Replace does nothing.",
     replace(WRONG, 0, bar("{k} Enter {/} Pick another file"),
             "{r}✗ Not the key of this host's root: pick the root key kept at install.{/}")),
    ("The right file", "Checked at once: the key matches the OpenVIBES root on this host.",
     replace(RIGHT, 1, bar("{k} Enter {/} Replace"), "{g}✓ The key matches the OpenVIBES root on this host.{/}")),
    ("Enter: the question", "Says why nothing breaks.",
     replace(RIGHT, 1, ask("Replace it?", "agents keep working"))),
    ("Yes: your password", "Asked in the bar, like Update and Repair.",
     replace(RIGHT, 1, bar(PW + "Replace", "{k} Esc {/} Cancel", nav=False))),
    ("Enter: it runs", "The same step list as Update; your own CA has no first step.",
     maint2b.steps(WHERE, "Replacing the intermediate", STEPS, 2, "ingest, distribution, console")),
    ("Done", "One result line; the key file is never kept on this host.",
     maint2b.steps(WHERE, "Replacing the intermediate", STEPS, 0, "", DONE)),
    ("Esc: Maintenance › Certificates", "The old intermediate stays trusted until its last agent certificate ends, "
     "then it goes by itself.",
     screen("limebox · Maintenance › Certificates",
            [header("Certificates"), ""] + certs2.info(AFTER) + [""] + menu(certs2.ACTS_OURS, 0, 26),
            bar("{k} Enter {/} Names"))),
]))
