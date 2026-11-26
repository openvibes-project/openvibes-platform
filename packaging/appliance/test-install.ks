
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
# signatures checked (#558), as Setup asks dnf for them.
ExecStart=/bin/sh -c 'rpm -q openvibes-admin postgresql17-server && test -f /etc/openvibes/appliance && systemctl is-active firewalld sshd chronyd && dnf -y -q --disablerepo=* --enablerepo=openvibes-appliance install openvibes-fetch openvibes-agent && echo OPENVIBES-BOOT-OK || echo OPENVIBES-BOOT-FAILED'
ExecStartPost=/usr/bin/systemctl poweroff
[Install]
WantedBy=multi-user.target
EOF
systemctl enable openvibes-boot-check.service
%end
