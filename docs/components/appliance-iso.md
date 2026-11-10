# appliance ISO

The OpenVIBES appliance: a bootable installer ISO that turns a blank machine
into an AlmaLinux 10 server running the platform (#529). It works offline and in
the terminal only. Installing on an existing system (RPMs, offline kit) is a
separate path and doesn't change.

## What the person sees

1. The boot menu starts **Install OpenVIBES (AlmaLinux 10.2)** after 3 seconds.
   Esc shows the menu (media test, basic graphics, rescue).
2. If a disk already holds the appliance (a `/boot/openvibes-appliance`
   marker, found by mounting plain file systems read-only), a screen says so
   first. **Enter** restarts, so remove the USB stick first; **i** installs again.
3. Four OpenVIBES screens on console 8 (`packaging/appliance/openvibes-installer.py`,
   Python curses in the installer image, run from the kickstart's `%pre`):
   - **Keyboard:** the common layouts by name first ("Swedish  se"), then
     every keymap. Type to filter; US is the default. The layout applies at
     once, so the password is typed in it, and the installed system keeps it.
   - **Disk:** every disk except the installer's own medium. Disks under 30 GB
     are greyed out with "30 GB is the minimum".
   - **Administrator:** name and password, typed twice, at least 12
     characters. The account is in `wheel`; root stays locked.
   - **Confirm:** nothing is written until `erase <disk>` is typed.
4. Anaconda installs unattended in text mode, then restarts. The person
   removes the USB stick (the confirm screen says so), signs in, and lands in
   the admin TUI's Setup. There's no second password: on the appliance only,
   `/etc/sudoers.d/openvibes-appliance` lets `wheel` run
   `/usr/bin/openvibes-admin`, with no arguments, without one. Every other
   sudo still asks. The TUI runs as root and has a shell, so a program running
   as the administrator can reach root through it; that's the trade for one
   password at the console.

## Interfaces

- `packaging/appliance/openvibes-appliance.ks`: the kickstart. `%include
  /tmp/openvibes-choice.ks` takes the screens' answers (`keyboard`, `ignoredisk`,
  `clearpart`, `autopart`, `bootloader`, and `user` with an SHA-512 hash from
  `openssl passwd -6`). Everything else is fixed here.
- `openvibes-installer.py [--console N] OUT`: writes those lines to OUT and
  exits 0. It exits 1 when the person powers off from the first screen.
  `--self-test` checks the name, password and kickstart rules.
- `scripts/build-appliance-iso.sh KIT_TAR OUT_ISO` (as root in `almalinux:10`):
  - starts from AlmaLinux's minimal ISO, checked against its signed checksums;
  - resolves the installer repository (`/openvibes-repo`) from the kit and
    AlmaLinux's current repositories (#546);
  - adds the kickstart and the screens, and edits both boot menus.

## Configuration

- `OPENVIBES_ISO_TEST=1` builds the CI test variant. The boot line gets
  `openvibes.unattended` (the screens are skipped, and `test-install.ks`
  supplies the disk, a user and a boot check) and a serial console.
- `OPENVIBES_KEY_FINGERPRINT` is the kit's package key, which CI's test kit
  uses.

## Failure behaviour

- If the screens fail or the person powers off, `%pre` fails, and Anaconda
  stops before any disk is touched.
- Without a disk of 30 GB or more, the disk screen says so and offers nothing.
- `%post` refuses a system with no administrator in `wheel`. The screens
  always create one, so this only guards against a broken kickstart.
- A machine that boots the installer again after the install (the stick
  left in, or BIOS boot order) gets the "already installed" screen, not the
  keyboard screen.

## How to test

- `python3 -I packaging/appliance/openvibes-installer.py --self-test`.
- CI builds the ISO and the test ISO on every change to them.
- `lab appliance --run <CI run>` in openvibes-lab installs the test ISO
  unattended on BIOS and UEFI and waits for the boot check.
- The interactive screens are tested in a lab VM, by sending keys with
  `virsh send-key` and checking each screen with `virsh screenshot`.
