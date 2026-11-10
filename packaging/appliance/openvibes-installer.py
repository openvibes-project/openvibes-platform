#!/usr/bin/python3 -I
"""The OpenVIBES appliance installer's screens (#549).

Runs in the kickstart's %pre, on a console of AlmaLinux's installer, before
anything is written: keyboard, disk, administrator, confirm. Writes the
kickstart lines for them to OUT (%include'd by openvibes-appliance.ks);
Anaconda then installs unattended. Nothing is erased until the confirm screen
has been answered with "erase <disk>".

Usage: openvibes-installer.py [--console N] OUT    (--self-test: check the rules)
--console N runs on /dev/ttyN as its own session and shows that console (in
%pre there is no terminal; console 6 is Anaconda's, so the kickstart uses 8).
"""

import curses
import fcntl
import json
import locale
import os
import re
import subprocess
import sys
import termios

MIN_DISK = 30 * 1024**3  # 30 GB, as lsblk and the screen count it (GiB)
MIN_PASSWORD = 12
STEPS = 4
NAME = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
TAKEN = {"root", "postgres", "admin", "lab"}  # admin: the console's own account


def gb(size):
    return f"{size / 1024**3:.0f} GB"


def name_problem(name):
    if not NAME.match(name):
        return "Use lowercase letters, digits, - and _ (start with a letter), at most 32."
    if name in TAKEN or name.startswith("openvibes"):
        return f"{name} is used by the system. Choose another name."
    return None


def password_problem(password, again):
    if len(password) < MIN_PASSWORD:
        return f"At least {MIN_PASSWORD} characters."
    if password != again:
        return "The passwords do not match."
    return None


def medium():
    """The disk this installer boots from (a USB stick), or None."""
    src = subprocess.run(["findmnt", "-no", "SOURCE", "/run/install/repo"],
                         capture_output=True, text=True).stdout.strip()
    if not src:
        return None
    parent = subprocess.run(["lsblk", "-no", "PKNAME", src], capture_output=True, text=True).stdout.split()
    return parent[0] if parent else os.path.basename(src)


def disks():
    """The disks to offer: (name, size, model, too_small). The installer's
    own medium is left out."""
    out = subprocess.run(["lsblk", "-J", "-b", "-d", "-o", "NAME,TYPE,SIZE,MODEL,RO"],
                         capture_output=True, text=True, check=True).stdout
    boot = medium()
    found = []
    for dev in json.loads(out)["blockdevices"]:
        if dev["type"] != "disk" or dev.get("ro") or dev["name"] == boot:
            continue
        if dev["name"].startswith(("zram", "loop")):
            continue
        size = int(dev["size"])
        found.append((dev["name"], size, (dev.get("model") or "").strip(), size < MIN_DISK))
    return found


# The common layouts, named, at the top of the list; every other keymap below.
COMMON = [("us", "English (US)"), ("gb", "English (UK)"), ("se", "Swedish"),
          ("no", "Norwegian"), ("dk", "Danish"), ("fi", "Finnish"), ("is", "Icelandic"),
          ("de", "German"), ("ch", "Swiss"), ("fr", "French"), ("be", "Belgian"),
          ("nl", "Dutch"), ("es", "Spanish"), ("pt", "Portuguese"), ("it", "Italian"),
          ("pl", "Polish"), ("cz", "Czech"), ("hu", "Hungarian"), ("ru", "Russian"),
          ("ua", "Ukrainian"), ("tr", "Turkish"), ("jp", "Japanese"), ("br", "Brazilian"),
          ("ca", "Canadian")]


def keymaps():
    """(keymap, label) pairs: the common named ones first, then the rest."""
    found = subprocess.run(["localectl", "list-keymaps", "--no-pager"],
                           capture_output=True, text=True).stdout.split()
    names = dict(COMMON)
    first = [(m, f"{names[m]:<16}{m}") for m, _ in COMMON if m in found or not found]
    rest = [(m, f"{'':<16}{m}") for m in found if m not in names]
    return first + rest


def kickstart(keymap, disk, name, password_hash):
    return "\n".join([
        f"keyboard --vckeymap={keymap}",
        f"ignoredisk --only-use={disk}",
        "zerombr",
        f"clearpart --all --initlabel --drives={disk}",
        "autopart --type=lvm",
        f"bootloader --boot-drive={disk}",
        f"user --name={name} --groups=wheel --iscrypted --password='{password_hash}'",
        "",
    ])


def crypt(password):
    return subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=password,
                          capture_output=True, text=True, check=True).stdout.strip()


class Screen:
    def __init__(self, win):
        self.win = win
        curses.curs_set(0)
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)  # selection
        curses.init_pair(2, curses.COLOR_RED, -1)  # problems

    def frame(self, step, keys):
        w = self.win
        w.erase()
        h, wd = w.getmaxyx()
        w.addstr(0, 1, "OpenVIBES appliance · Install", curses.A_BOLD)
        w.addstr(0, wd - 8, f"{step} of {STEPS}")
        w.hline(1, 0, curses.ACS_HLINE, wd)
        w.hline(h - 2, 0, curses.ACS_HLINE, wd)
        w.addstr(h - 1, 1, keys[: wd - 2])
        return h, wd

    def keyboard(self, maps, current):
        keys = [m for m, _ in maps]
        typed, pick = "", keys.index(current) if current in keys else 0
        while True:
            shown = [(m, label) for m, label in maps if typed.lower() in label.lower()]
            pick = max(0, min(pick, len(shown) - 1))
            h, wd = self.frame(1, "type to filter   ↑↓ choose   Enter next   Esc power off")
            self.win.addstr(3, 1, "Choose the keyboard layout. It applies now, so the password is typed in it.")
            self.win.addstr(5, 3, f"Filter  {typed}_")
            if not shown:
                self.win.addstr(7, 3, "No layout matches. Backspace to change the filter.", curses.color_pair(2))
            rows = h - 10
            top = min(max(0, pick - rows // 2), max(0, len(shown) - rows))
            for i, (_, label) in enumerate(shown[top: top + rows]):
                attr = curses.color_pair(1) if top + i == pick else 0
                self.win.addstr(7 + i, 3, f" {label:<40}"[: wd - 4], attr)
            k = self.win.get_wch()
            if k in ("\n", "\r", curses.KEY_ENTER):
                if shown:
                    return shown[pick][0]
            if k == "\x1b":
                return None
            if k == curses.KEY_UP:
                pick = max(0, pick - 1)
            elif k == curses.KEY_DOWN:
                pick = min(len(shown) - 1, pick + 1)
            elif k in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                typed, pick = typed[:-1], 0
            elif isinstance(k, str) and k.isprintable():
                typed, pick = typed + k, 0

    def disk(self, found, pick):
        usable = [i for i, d in enumerate(found) if not d[3]]
        while True:
            self.frame(2, "↑↓ choose   Enter next   Esc back")
            self.win.addstr(3, 1, "Choose the disk to install on. Everything on it is erased.")
            if not usable:
                self.win.addstr(5, 3, "No disk of 30 GB or more was found.", curses.color_pair(2))
            for i, (name, size, model, small) in enumerate(found):
                line = f" {name:<8}{gb(size):>9}   {model}"
                if small:
                    line += "   (30 GB is the minimum)"
                attr = curses.A_DIM if small else (curses.color_pair(1) if i == pick else 0)
                self.win.addstr(6 + i, 3, line, attr)
            k = self.win.get_wch()
            if k == "\x1b":
                return None
            if k in ("\n", "\r", curses.KEY_ENTER) and pick in usable:
                return pick
            step = -1 if k == curses.KEY_UP else 1 if k == curses.KEY_DOWN else 0
            if step and usable:
                later = [i for i in usable if (i - pick) * step > 0]
                if later:
                    pick = min(later, key=lambda i: abs(i - pick))

    def field(self, y, x, value, secret, active):
        shown = "*" * len(value) if secret else value
        self.win.addstr(y, x, shown + ("_" if active else " "), curses.A_BOLD if active else 0)

    def admin(self, name):
        values, at, problem = [name, "", ""], 0, None
        labels = ["Name", "Password", "Again"]
        while True:
            self.frame(3, "Tab next field   Enter next   Esc back")
            self.win.addstr(3, 1, "The administrator signs in on this console and over SSH, and runs")
            self.win.addstr(4, 1, "openvibes-admin. root stays locked.")
            for i, label in enumerate(labels):
                self.win.addstr(6 + i, 3, f"{label:<11}")
                self.field(6 + i, 14, values[i], i > 0, i == at)
            self.win.addstr(10, 3, f"At least {MIN_PASSWORD} characters.")
            if problem:
                self.win.addstr(12, 3, problem, curses.color_pair(2))
            k = self.win.get_wch()
            if k == "\x1b":
                return None
            if k == "\t" or k == curses.KEY_DOWN:
                at = (at + 1) % 3
            elif k == curses.KEY_UP:
                at = (at - 1) % 3
            elif k in ("\n", "\r", curses.KEY_ENTER):
                if at < 2:
                    at += 1
                    continue
                problem = name_problem(values[0]) or password_problem(values[1], values[2])
                if not problem:
                    return values[0], values[1]
                at = 0 if name_problem(values[0]) else 1
                values[1] = values[2] = ""
            elif k in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                values[at] = values[at][:-1]
            elif isinstance(k, str) and k.isprintable():
                values[at] += k

    def confirm(self, disk, admin):
        typed, want = "", f"erase {disk[0]}"
        while True:
            self.frame(4, "Enter install   Esc back")
            self.win.addstr(3, 1, "Ready to install:")
            what = ", ".join(part for part in (disk[0], gb(disk[1]), disk[2]) if part)
            self.win.addstr(5, 3, f"Disk            {what}: ERASED")
            self.win.addstr(6, 3, f"Administrator   {admin}")
            self.win.addstr(7, 3, "Network         DHCP (a static address is set in Setup afterwards)")
            self.win.addstr(13, 1, "The machine restarts when the install is done: remove the USB stick then,")
            self.win.addstr(14, 1, "or it starts this installer again.")
            self.win.addstr(9, 3, "Type  ")
            self.win.addstr(want, curses.A_BOLD)
            self.win.addstr("  to start.")
            self.win.addstr(11, 3, f"> {typed}_")
            k = self.win.get_wch()
            if k == "\x1b":
                return False
            if k in ("\n", "\r", curses.KEY_ENTER) and typed == want:
                return True
            if k in (curses.KEY_BACKSPACE, "\x7f", "\b"):
                typed = typed[:-1]
            elif isinstance(k, str) and k.isprintable():
                typed += k


def run(win):
    curses.set_escdelay(25)  # Esc answers at once, not after 1 s
    s = Screen(win)
    maps, found = keymaps(), disks()
    keymap, pick, name, step = "us", next((i for i, d in enumerate(found) if not d[3]), 0), "", 1
    while True:
        if step == 1:
            chosen = s.keyboard(maps, keymap)
            if chosen is None:
                subprocess.run(["systemctl", "poweroff"])
                return None
            keymap = chosen
            subprocess.run(["loadkeys", keymap], capture_output=True)
            step = 2
        elif step == 2:
            chosen = s.disk(found, pick)
            step, pick = (1, pick) if chosen is None else (3, chosen)
        elif step == 3:
            got = s.admin(name)
            if got is None:
                step = 2
                continue
            name, password = got
            step = 4
        else:
            if s.confirm(found[pick], name):
                return kickstart(keymap, found[pick][0], name, crypt(password))
            step = 3


def self_test():
    assert name_problem("lime") is None
    assert name_problem("Lime") and name_problem("1x") and name_problem("root")
    assert name_problem("openvibes-ingest") and name_problem("a" * 33)
    assert password_problem("short", "short")
    assert password_problem("a" * 12, "b" * 12)
    assert password_problem("a" * 12, "a" * 12) is None
    ks = kickstart("se", "vda", "lime", "$6$salt$hash")
    assert "keyboard --vckeymap=se\n" in ks and "--drives=vda\n" in ks
    assert "user --name=lime --groups=wheel --iscrypted --password='$6$salt$hash'" in ks
    print("ok")


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        self_test()
        sys.exit(0)
    args = sys.argv[1:]
    if args[:1] == ["--console"] and len(args) == 3:
        tty = f"/dev/tty{int(args[1])}"
        os.setsid()
        fd = os.open(tty, os.O_RDWR)
        fcntl.ioctl(fd, termios.TIOCSCTTY, 1)
        for std in (0, 1, 2):
            os.dup2(fd, std)
        subprocess.run(["chvt", args[1]], check=True)
        args = args[2:]
    if len(args) != 1:
        sys.exit(__doc__)
    os.environ.setdefault("TERM", "linux")
    locale.setlocale(locale.LC_ALL, "")  # curses draws ·, ↑↓ and • only in a UTF-8 locale
    lines = curses.wrapper(run)
    if lines is None:
        sys.exit(1)
    with open(args[0], "w", encoding="utf-8") as out:
        out.write(lines)
