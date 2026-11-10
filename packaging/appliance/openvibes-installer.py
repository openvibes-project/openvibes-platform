#!/usr/bin/python3 -I
"""The OpenVIBES appliance installer's screens (#549).

Runs in the kickstart's %pre, on a console of AlmaLinux's installer, before
anything is written: keyboard, disk, administrator, confirm. Writes the
kickstart lines for them to OUT (%include'd by openvibes-appliance.ks);
Anaconda then installs unattended. Nothing is erased until the confirm screen
has been answered with "erase <disk>".

Usage: openvibes-installer.py [--console N] 3>OUT    (--self-test: check the rules)
The kickstart lines go to file descriptor 3, which the caller opens on OUT.
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
import tempfile
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


MARKER = "openvibes-appliance"  # on /boot, written by the kickstart's %post


def installed(boot):
    """(disk, date) for every disk that holds an installed appliance: its
    /boot carries MARKER. Each plain file system is mounted read-only for a
    look; any that will not mount is skipped."""
    out = subprocess.run(["lsblk", "-J", "-o", "NAME,FSTYPE,PKNAME,TYPE"],
                         capture_output=True, text=True).stdout
    found, where = [], tempfile.mkdtemp(prefix="openvibes-look-")

    def walk(devs):
        for dev in devs:
            yield dev
            yield from walk(dev.get("children", []))

    for dev in walk(json.loads(out or '{"blockdevices": []}')["blockdevices"]):
        if dev.get("type") != "part" or dev.get("fstype") not in ("xfs", "ext4") or dev.get("pkname") == boot:
            continue
        opts = "ro,norecovery" if dev["fstype"] == "xfs" else "ro"
        if subprocess.run(["mount", "-o", opts, f"/dev/{dev['name']}", where], capture_output=True).returncode:
            continue
        try:
            with open(os.path.join(where, MARKER), encoding="utf-8") as f:
                found.append((dev["pkname"], f.read().strip()))
        except OSError:
            pass
        finally:
            subprocess.run(["umount", where], capture_output=True)
    os.rmdir(where)
    return found


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


ENTER = ("\n", "\r", curses.KEY_ENTER)
ESC = "\x1b"
ERASE = (curses.KEY_BACKSPACE, "\x7f", "\b")


def edited(text, k):
    """text after the key k when k edits it (Backspace or a character), else None."""
    if k in ERASE:
        return text[:-1]
    if isinstance(k, str) and k.isprintable():
        return text + k
    return None


def nearest(usable, pick, k):
    """The usable row next to pick in the direction of an arrow key k."""
    step = {curses.KEY_UP: -1, curses.KEY_DOWN: 1}.get(k)
    later = [i for i in usable if step and (i - pick) * step > 0]
    return min(later, key=lambda i: abs(i - pick)) if later else pick


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
        if step:
            w.addstr(0, wd - 8, f"{step} of {STEPS}")
        w.hline(1, 0, curses.ACS_HLINE, wd)
        w.hline(h - 2, 0, curses.ACS_HLINE, wd)
        w.addstr(h - 1, 1, keys[: wd - 2])
        return h, wd

    def already(self, found):
        """True: install again. Restarts the machine otherwise."""
        while True:
            self.frame(0, "Enter restart   i install again")
            self.win.addstr(3, 1, "OpenVIBES is already installed here:")
            for i, (disk, date) in enumerate(found):
                self.win.addstr(5 + i, 3, f"{disk:<8} installed {date}")
            y = 6 + len(found)
            self.win.addstr(y, 1, "If you have just installed it, remove the USB stick and restart: the")
            self.win.addstr(y + 1, 1, "machine then starts OpenVIBES. Install again only to erase it and start over.")
            k = self.win.get_wch()
            if k in ("i", "I"):
                return True
            if k in ENTER:
                subprocess.run(["systemctl", "reboot"])
                return False

    def draw_keyboard(self, shown, typed, pick):
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

    def keyboard(self, maps, current):
        keys = [m for m, _ in maps]
        typed, pick = "", keys.index(current) if current in keys else 0
        while True:
            shown = [(m, label) for m, label in maps if typed.lower() in label.lower()]
            pick = max(0, min(pick, len(shown) - 1))
            self.draw_keyboard(shown, typed, pick)
            k = self.win.get_wch()
            if k in ENTER and shown:
                return shown[pick][0]
            if k == ESC:
                return None
            if k in (curses.KEY_UP, curses.KEY_DOWN):
                pick += 1 if k == curses.KEY_DOWN else -1
            elif (new := edited(typed, k)) is not None:
                typed, pick = new, 0

    def draw_disks(self, found, pick, usable):
        self.frame(2, "↑↓ choose   Enter next   Esc back")
        self.win.addstr(3, 1, "Choose the disk to install on. Everything on it is erased.")
        if not usable:
            self.win.addstr(5, 3, "No disk of 30 GB or more was found.", curses.color_pair(2))
        for i, (name, size, model, small) in enumerate(found):
            line = f" {name:<8}{gb(size):>9}   {model}"
            attr = curses.color_pair(1) if i == pick else 0
            if small:
                line, attr = line + "   (30 GB is the minimum)", curses.A_DIM
            self.win.addstr(6 + i, 3, line, attr)

    def disk(self, found, pick):
        usable = [i for i, d in enumerate(found) if not d[3]]
        while True:
            self.draw_disks(found, pick, usable)
            k = self.win.get_wch()
            if k == ESC:
                return None
            if k in ENTER and pick in usable:
                return pick
            pick = nearest(usable, pick, k)

    def field(self, y, x, value, secret, active):
        shown = "*" * len(value) if secret else value
        self.win.addstr(y, x, shown + ("_" if active else " "), curses.A_BOLD if active else 0)

    def draw_admin(self, values, at, problem):
        self.frame(3, "Tab next field   Enter next   Esc back")
        self.win.addstr(3, 1, "The administrator signs in on this console and over SSH, and runs")
        self.win.addstr(4, 1, "openvibes-admin. root stays locked.")
        for i, label in enumerate(["Name", "Password", "Again"]):
            self.win.addstr(6 + i, 3, f"{label:<11}")
            self.field(6 + i, 14, values[i], i > 0, i == at)
        self.win.addstr(10, 3, f"At least {MIN_PASSWORD} characters.")
        if problem:
            self.win.addstr(12, 3, problem, curses.color_pair(2))

    def admin(self, name):
        values, at, problem = [name, "", ""], 0, None
        while True:
            self.draw_admin(values, at, problem)
            k = self.win.get_wch()
            if k == ESC:
                return None
            moves = {"\t": 1, curses.KEY_DOWN: 1, curses.KEY_UP: -1}
            if k in moves:
                at = (at + moves[k]) % 3
            elif k in ENTER and at < 2:
                at += 1
            elif k in ENTER:
                problem = name_problem(values[0]) or password_problem(values[1], values[2])
                if not problem:
                    return values[0], values[1]
                at = 0 if name_problem(values[0]) else 1
                values[1] = values[2] = ""
            elif (new := edited(values[at], k)) is not None:
                values[at] = new

    def draw_confirm(self, disk, admin, want, typed):
        self.frame(4, "Enter install   Esc back")
        self.win.addstr(3, 1, "Ready to install:")
        what = ", ".join(part for part in (disk[0], gb(disk[1]), disk[2]) if part)
        self.win.addstr(5, 3, f"Disk            {what}: ERASED")
        self.win.addstr(6, 3, f"Administrator   {admin}")
        self.win.addstr(7, 3, "Network         DHCP (a static address is set in Setup afterwards)")
        self.win.addstr(9, 3, "Type  ")
        self.win.addstr(want, curses.A_BOLD)
        self.win.addstr("  to start.")
        self.win.addstr(11, 3, f"> {typed}_")
        self.win.addstr(13, 1, "The machine restarts when the install is done: remove the USB stick then,")
        self.win.addstr(14, 1, "or it starts this installer again.")

    def confirm(self, disk, admin):
        typed, want = "", f"erase {disk[0]}"
        while True:
            self.draw_confirm(disk, admin, want, typed)
            k = self.win.get_wch()
            if k == ESC:
                return False
            if k in ENTER and typed == want:
                return True
            if (new := edited(typed, k)) is not None:
                typed = new


class Flow:
    """The four screens in order; Esc goes one back. Each step returns the
    next one (1 to 4), or 0 when the answers are complete."""

    def __init__(self, screen):
        self.s = screen
        self.maps, self.found = keymaps(), disks()
        self.keymap, self.name, self.password = "us", "", ""
        self.pick = next((i for i, d in enumerate(self.found) if not d[3]), 0)

    def keyboard(self):
        chosen = self.s.keyboard(self.maps, self.keymap)
        if chosen is None:
            subprocess.run(["systemctl", "poweroff"])
            raise SystemExit(1)
        self.keymap = chosen
        subprocess.run(["loadkeys", chosen], capture_output=True)
        return 2

    def disk(self):
        chosen = self.s.disk(self.found, self.pick)
        if chosen is None:
            return 1
        self.pick = chosen
        return 3

    def admin(self):
        got = self.s.admin(self.name)
        if got is None:
            return 2
        self.name, self.password = got
        return 4

    def confirm(self):
        return 0 if self.s.confirm(self.found[self.pick], self.name) else 3

    def run(self):
        steps = {1: self.keyboard, 2: self.disk, 3: self.admin, 4: self.confirm}
        step = 1
        while step:
            step = steps[step]()
        return kickstart(self.keymap, self.found[self.pick][0], self.name, crypt(self.password))


def run(win):
    curses.set_escdelay(25)  # Esc answers at once, not after 1 s
    s = Screen(win)
    there = installed(medium())
    if there and not s.already(there):
        return None
    return Flow(s).run()


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
    if args[:1] == ["--console"] and len(args) == 2:
        tty = f"/dev/tty{int(args[1])}"
        os.setsid()
        fd = os.open(tty, os.O_RDWR)
        fcntl.ioctl(fd, termios.TIOCSCTTY, 1)
        for std in (0, 1, 2):
            os.dup2(fd, std)
        subprocess.run(["chvt", args[1]], check=True)
        args = args[2:]
    if args:
        sys.exit(__doc__)
    try:
        out = os.fdopen(3, "w", encoding="utf-8")
    except OSError:
        sys.exit("file descriptor 3 must be open for the kickstart lines (3>FILE)")
    os.environ.setdefault("TERM", "linux")
    locale.setlocale(locale.LC_ALL, "")  # curses draws ·, ↑↓ and • only in a UTF-8 locale
    lines = curses.wrapper(run)
    if lines is None:
        sys.exit(1)
    with out:
        out.write(lines)
