# The OpenVIBES appliance installer (AlmaLinux 10).
#
# Asks only for what is yours: the disk, the language and keyboard, the
# network, and the administrator's name and password (root stays locked).
# Everything else is decided here. The OpenVIBES packages and PostgreSQL 17
# come from the offline kit on this disk; nothing is downloaded. After the
# restart the administrator logs in, lands in the admin TUI and finishes with
# Setup.

lang en_US.UTF-8
keyboard us
timezone UTC --utc
network --bootproto=dhcp --activate --onboot=yes
rootpw --lock
selinux --enforcing
firewall --enabled --ssh
services --enabled=sshd,chronyd,NetworkManager,firewalld
zerombr
clearpart --all --initlabel
autopart --type=lvm
bootloader --location=mbr
reboot --eject

# The kit's package folder, on this disk (the build script adds it).
repo --name=openvibes --baseurl=file:///run/install/repo/openvibes-offline/packages

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

%post --erroronfail
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
%end
