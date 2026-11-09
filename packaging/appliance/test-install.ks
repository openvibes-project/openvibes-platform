
# CI only: added to the kickstart in the test ISO (build-appliance-iso.sh with
# OPENVIBES_ISO_TEST=1), so the install runs by itself in QEMU and the
# installed system proves it started. Never part of the released ISO.
ignoredisk --only-use=vda
zerombr
clearpart --all --initlabel
autopart --type=lvm
bootloader --append="console=ttyS0,115200n8"
user --name=tester --groups=wheel --password=tester --plaintext
text
poweroff

%post
cat > /etc/systemd/system/openvibes-boot-check.service <<'EOF'
[Unit]
Description=OpenVIBES boot check (CI only)
After=multi-user.target
[Service]
Type=oneshot
StandardOutput=journal+console
ExecStart=/bin/sh -c 'rpm -q openvibes-admin postgresql17-server && test -f /etc/openvibes/appliance && systemctl is-active firewalld sshd chronyd && echo OPENVIBES-BOOT-OK || echo OPENVIBES-BOOT-FAILED'
ExecStartPost=/usr/bin/systemctl poweroff
[Install]
WantedBy=multi-user.target
EOF
systemctl enable openvibes-boot-check.service
%end
