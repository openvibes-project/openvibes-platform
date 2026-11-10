# The OpenVIBES appliance installer (AlmaLinux 10), terminal only (#549).
#
# Before anything is written, OpenVIBES screens (openvibes-installer.py, from
# %pre below) ask for what is yours: the keyboard, the disk (erased only after
# "erase <disk>" is typed) and the administrator (name and password; in wheel,
# root stays locked). Their answers are %include'd; everything else is decided
# here and Anaconda installs unattended in text mode. The OpenVIBES packages
# and PostgreSQL 17 come from this disk; nothing is downloaded. After the
# restart the administrator logs in, lands in the admin TUI and finishes with
# Setup.

lang en_US.UTF-8
text
%include /tmp/openvibes-choice.ks
timezone UTC --utc
network --bootproto=dhcp --activate --onboot=yes
rootpw --lock
selinux --enforcing
firewall --enabled --ssh
services --enabled=sshd,chronyd,NetworkManager,firewalld
reboot --eject

# The installer's repository on this disk: every package the system gets,
# current and consistent (the build script resolves it, #546).
repo --name=openvibes --baseurl=file:///run/install/repo/openvibes-repo

%packages
@^minimal-environment
chrony
firewalld
NetworkManager
sudo
openvibes-admin
openvibes-console
openvibes-ingest
openvibes-distribution
openvibes-vulns
openvibes-signer
openvibes-llm
openvibes-llm-model
openvibes-rules-*
postgresql17-server
%end

# The screens run on console 8 (TERM=linux: Anaconda's own is tmux's, which
# the installer image has no description of; LC_ALL=C.UTF-8 for the dots and
# arrows); their answers go to /tmp/openvibes-choice.ks.
# The CI test ISO (openvibes.unattended) brings its own disk and user lines.
%pre --erroronfail
if grep -qw openvibes.unattended /proc/cmdline; then
    echo "keyboard --vckeymap=us" > /tmp/openvibes-choice.ks
else
    TERM=linux LC_ALL=C.UTF-8 python3 -I /run/install/repo/openvibes-installer.py --console 8 /tmp/openvibes-choice.ks || exit 1
    chvt 1
fi
%end

%post --erroronfail
# The login runs the TUI through sudo, so a normal user must be in wheel
# (root is locked). Fail loudly now rather than leave an unusable box.
admins=$(getent group wheel | cut -d: -f4)
ok=
for u in $(awk -F: '$3 >= 1000 && $3 < 60000 {print $1}' /etc/passwd); do
    case ",$admins," in *",$u,"*) ok=1 ;; esac
done
[ -n "$ok" ] || { echo "No administrator: tick 'Make this user administrator' when creating the user." >&2; exit 1; }

# This host is the appliance: the admin TUI shows System and Log out.
install -d -m 0755 /etc/openvibes
: > /etc/openvibes/appliance

# The login is the admin TUI. Log out ends the session; if the TUI fails,
# the shell stays so the problem can be looked at.
cat > /etc/profile.d/openvibes-appliance.sh <<'EOF'
if [ -f /etc/openvibes/appliance ] && [ -t 0 ] && [ "$(id -u)" != 0 ] && [ -z "${OPENVIBES_NO_TUI:-}" ]; then
    sudo /usr/bin/openvibes-admin && exit
fi
EOF
chmod 0644 /etc/profile.d/openvibes-appliance.sh

# The login just asked for the password: the admin TUI opens without a
# second prompt (lime, 2026-11-10). Only that program with no arguments, only
# for wheel, only on the appliance; every other sudo still asks.
cat > /etc/sudoers.d/openvibes-appliance <<'EOF'
# The appliance's login opens the admin TUI without a second password.
%wheel ALL=(root) NOPASSWD: /usr/bin/openvibes-admin ""
EOF
chmod 0440 /etc/sudoers.d/openvibes-appliance
visudo -cqf /etc/sudoers.d/openvibes-appliance

# The installer's screens find this on /boot (a plain partition, no LVM) and
# say OpenVIBES is already installed when the USB stick was left in (#549).
date -u +%F > /boot/openvibes-appliance
%end
