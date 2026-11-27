
# CI only: added to the kickstart in the test ISO (build-appliance-iso.sh with
# OPENVIBES_ISO_TEST=1), so the install runs by itself in QEMU and the
# installed system proves it started. Never part of the released ISO.
ignoredisk --only-use=vda
zerombr
clearpart --all --initlabel
autopart --type=lvm
bootloader --append="console=ttyS0,115200n8"
user --name=tester --groups=wheel --password=tester --plaintext
poweroff

%post
cat > /etc/systemd/system/openvibes-boot-check.service <<'EOF'
[Unit]
Description=OpenVIBES boot check (CI only)
After=multi-user.target
[Service]
Type=oneshot
StandardOutput=journal+console
# Setup's optional packages install from the appliance's own source only,
# signatures checked (#558), as Setup asks dnf for them. Cockpit is closed
# and semanage is there for a new SSH port (#561). Passwords are the first
# account's only and SSH opens the TUI (#562). The console signs in on
# OpenVIBES' screen, with faillock on (#565).
ExecStart=/bin/sh -c 'rpm -q openvibes-admin postgresql17-server && test -f /etc/openvibes/appliance && systemctl is-active firewalld sshd chronyd && ! firewall-cmd --permanent --query-service=cockpit && test -x /usr/sbin/semanage && sshd -t && sshd -T -C user=nobody,host=x,addr=192.0.2.1 | grep -qix "passwordauthentication no" && sshd -T -C user=tester,host=x,addr=192.0.2.1 | grep -qix "passwordauthentication yes" && sshd -T | grep -qi "^forcecommand /usr/libexec/openvibes/appliance-ssh" && systemctl cat getty@tty1.service | grep -q "login-program /usr/bin/openvibes-admin --login-options signin" && authselect current | grep -q with-faillock && dnf -y -q --disablerepo=* --enablerepo=openvibes-appliance install openvibes-fetch openvibes-agent && echo OPENVIBES-BOOT-OK || echo OPENVIBES-BOOT-FAILED'
ExecStartPost=/usr/bin/systemctl poweroff
[Install]
WantedBy=multi-user.target
EOF
systemctl enable openvibes-boot-check.service
%end
