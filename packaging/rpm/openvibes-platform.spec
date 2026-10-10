# Binary packaging: scripts/build-rpm.sh builds the release binaries with
# the pinned toolchain first; this spec only installs them.
%global debug_package %{nil}
# openvibes-llm: scripts/build-llama-server.sh builds llama-server first
# (skip with --without llm); the Vulkan variant with --with vulkan.
%bcond llm 1
%bcond vulkan 0

# Upgrade from openvibes_NAME service accounts (admin TUI spec §2): rename
# the OS user and group before the new files are laid down. Inline because on
# the first upgrade no file of the new package exists yet. Stops the unit (and
# timer) first, remembering whether it ran; %%posttrans starts it again. If a
# process still runs as the old user, usermod could not rename it: start the
# unit again, remove the empty new account rpm may already have created from
# the sysusers file, and refuse, so rpm skips this package and the install
# stays consistent on the old name.
# An empty new account rpm may have created from the sysusers file is removed
# just before the rename. %%post then renames the PostgreSQL role.
%define rename_pre() \
old=openvibes_%1; new=openvibes-%1; \
if getent passwd $old >/dev/null; then \
    for u in %2 %{?3}; do systemctl is-active -q $u && touch /run/openvibes-restart-$u; systemctl stop $u 2>/dev/null; done; \
    if pgrep -u $old >/dev/null; then \
        echo "openvibes: processes still run as $old (PIDs $(pgrep -d, -u $old)); stop them and upgrade again" >&2; \
        for u in %2 %{?3}; do [ -e /run/openvibes-restart-$u ] && rm -f /run/openvibes-restart-$u && systemctl start $u; done; \
        getent passwd $new >/dev/null && userdel $new; getent group $new >/dev/null && groupdel $new; exit 1; \
    fi; \
    if getent passwd $new >/dev/null; then userdel $new || exit 1; fi; \
    if getent group $new >/dev/null && ! getent group $old >/dev/null; then :; elif getent group $new >/dev/null; then groupdel $new || exit 1; fi; \
    usermod -l $new $old || exit 1; \
fi; \
if getent group $old >/dev/null && ! getent group $new >/dev/null; then groupmod -n $new $old || exit 1; fi; :

# After the whole transaction: start again what %%rename_pre stopped, with the
# new units (User=openvibes-NAME) loaded.
%define restart_renamed() \
for u in %1 %{?2}; do \
    if [ -e /run/openvibes-restart-$u ]; then rm -f /run/openvibes-restart-$u; systemctl daemon-reload; systemctl start $u || :; fi; \
done; :

Name:           openvibes-platform
Version:        %{ov_version}
# Release builds use 1; CI builds pass ov_release=1.1.ci<run>, which sorts
# above the published 0.x.y-1 and below the next version, so a test
# install never looks identical to the published package (board #88).
Release:        %{?ov_release}%{!?ov_release:1}%{?dist}
Summary:        OpenVIBES platform services
License:        MIT
URL:            https://github.com/openvibes-project/openvibes-platform
BuildRequires:  systemd-rpm-macros

%description
OpenVIBES platform services.

%package -n openvibes-ingest
Requires(pre):  shadow-utils procps-ng systemd
Summary:        OpenVIBES agent-facing ingest service
%{?systemd_requires}

%description -n openvibes-ingest
Receives enrollments, renewals, heartbeats, and findings from OpenVIBES agents over mTLS.

%package -n openvibes-distribution
Requires(pre):  shadow-utils procps-ng systemd
Summary:        OpenVIBES rule distribution service
%{?systemd_requires}

%description -n openvibes-distribution
Serves operator-published, offline-signed rule bundles to enrolled OpenVIBES agents over mTLS.

%package -n openvibes-vulns
Requires(pre):  shadow-utils procps-ng systemd
Summary:        OpenVIBES vulnerability feeds and matching
%{?systemd_requires}

%description -n openvibes-vulns
Fetches Fedora security advisories and matches them against the package
inventories OpenVIBES agents report.

%package -n openvibes-admin
Requires(pre):  shadow-utils procps-ng systemd
# The administration TUI: operators act through sudo, polkit and curl;
# Setup checks ports with ss (iproute).
Requires:       sudo polkit curl iproute
# admin ships the migrations: an older console refuses the new schema and
# stays down, so dnf must upgrade the console with it (a fresh install
# without a console is unaffected).
Conflicts:      openvibes-console < %{version}
Summary:        OpenVIBES operator CLI and maintenance timer
%{?systemd_requires}

%description -n openvibes-admin
Schema migration, built-in CA, tokens, agents, and daily partition maintenance.

%package -n openvibes-signer
Summary:        OpenVIBES rule signer for the site's own rules
License:        MIT
# Its state directory's group is openvibes-operators, from openvibes-admin.
Requires:       openvibes-admin = %{version}-%{release}
Requires(pre):  openvibes-admin = %{version}-%{release}
%{?systemd_requires}

%description -n openvibes-signer
Holds the site rule-signing key and signs the site's own rule sets for the
console, only after checking the publishing user's password and permission
itself. Listens on a Unix socket only the console can reach.

%if %{with llm}
%package -n openvibes-llm
Requires(pre):  shadow-utils procps-ng systemd
Summary:        OpenVIBES local model server for the console's assistant
License:        MIT
# Models are installed with openvibes-admin, whose group owns the model store.
Requires:       openvibes-admin = %{version}-%{release}
# The model store's group is openvibes-admin, renamed in that package's %%pre.
Requires(pre):  openvibes-admin = %{version}-%{release}
%{?systemd_requires}
# The SELinux module (packaging/llm/openvibes-llm.cil) is loaded and removed
# with semodule.
Requires(post): policycoreutils
Requires(postun): policycoreutils

Recommends:     openvibes-llm-model = %{version}-%{release}

%description -n openvibes-llm
llama.cpp's llama-server from a pinned build (no subprocesses, RPC, TLS, or
web UI), run on loopback as its own sandboxed user with a model file whose
SHA-256 is pinned. Optional: the platform works without it.

# No model bytes: openvibes-admin Setup downloads the model (model fetch).
# This package only owns its path and model.conf, so upgrading from 0.2.5
# (which shipped the model) does not delete the user's model file.
%package -n openvibes-llm-model
Summary:        Model selection for the OpenVIBES local model server (no model bytes)
License:        MIT
Requires:       openvibes-llm = %{version}-%{release}
Obsoletes:      openvibes-llm-model-part1 < %{version}-%{release}
Obsoletes:      openvibes-llm-model-part2 < %{version}-%{release}

%description -n openvibes-llm-model
Selects the pinned model (Qwen3.5-4B Q4_K_M, packaging/llm/model.pin) for
openvibes-llm and owns its path, so upgrades keep an installed model. The
2.7 GB file is not packaged: openvibes-admin
Setup downloads it when the assistant is turned on (offline: see the
offline install guide).

%if %{with vulkan}
%package -n openvibes-llm-vulkan
Summary:        GPU (Vulkan) build of the OpenVIBES local model server
License:        MIT
Requires:       openvibes-llm = %{version}-%{release}

%description -n openvibes-llm-vulkan
The same pinned llama-server built for Vulkan (NVIDIA, AMD, Intel GPUs), and
a drop-in that runs openvibes-llm with it and with access to the GPU only.
%endif
%endif

%install
S=%{_sourcedir}
install -D -m 0755 $S/target/release/openvibes-ingest %{buildroot}%{_bindir}/openvibes-ingest
install -D -m 0755 $S/target/release/openvibes-admin %{buildroot}%{_bindir}/openvibes-admin
install -D -m 0755 $S/target/release/openvibes-distribution %{buildroot}%{_bindir}/openvibes-distribution
install -D -m 0644 $S/packaging/rpm/openvibes-distribution.service %{buildroot}%{_unitdir}/openvibes-distribution.service
install -D -m 0644 $S/packaging/rpm/openvibes-distribution.sysusers %{buildroot}%{_sysusersdir}/openvibes-distribution.conf
install -D -m 0640 $S/packaging/rpm/distribution.toml %{buildroot}%{_sysconfdir}/openvibes/distribution.toml
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-distribution/LICENSE
install -D -m 0755 $S/target/release/openvibes-signer %{buildroot}%{_bindir}/openvibes-signer
install -D -m 0644 $S/packaging/rpm/openvibes-signer.service %{buildroot}%{_unitdir}/openvibes-signer.service
install -D -m 0644 $S/packaging/rpm/openvibes-signer.sysusers %{buildroot}%{_sysusersdir}/openvibes-signer.conf
install -D -m 0640 $S/packaging/rpm/signer.toml %{buildroot}%{_sysconfdir}/openvibes/signer.toml
install -d -m 2750 %{buildroot}%{_sharedstatedir}/openvibes-signer
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-signer/LICENSE
install -D -m 0755 $S/target/release/openvibes-vulns %{buildroot}%{_bindir}/openvibes-vulns
install -D -m 0644 $S/packaging/rpm/openvibes-vulns.service %{buildroot}%{_unitdir}/openvibes-vulns.service
install -D -m 0644 $S/packaging/rpm/openvibes-vulns.sysusers %{buildroot}%{_sysusersdir}/openvibes-vulns.conf
install -D -m 0640 $S/packaging/rpm/vulns.toml %{buildroot}%{_sysconfdir}/openvibes/vulns.toml
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-vulns/LICENSE
install -D -m 0644 $S/packaging/rpm/openvibes-ingest.service %{buildroot}%{_unitdir}/openvibes-ingest.service
install -D -m 0644 $S/packaging/rpm/openvibes-maintenance.service %{buildroot}%{_unitdir}/openvibes-maintenance.service
install -D -m 0644 $S/packaging/rpm/openvibes-maintenance.timer %{buildroot}%{_unitdir}/openvibes-maintenance.timer
install -D -m 0644 $S/packaging/rpm/openvibes-migrate.service %{buildroot}%{_unitdir}/openvibes-migrate.service
install -D -m 0644 $S/packaging/rpm/openvibes-rules-apply.service %{buildroot}%{_unitdir}/openvibes-rules-apply.service
install -D -m 0644 $S/packaging/rpm/openvibes-ingest.sysusers %{buildroot}%{_sysusersdir}/openvibes-ingest.conf
install -D -m 0644 $S/packaging/rpm/openvibes-admin.sysusers %{buildroot}%{_sysusersdir}/openvibes-admin.conf
install -D -m 0640 $S/packaging/rpm/ingest.toml %{buildroot}%{_sysconfdir}/openvibes/ingest.toml
install -D -m 0640 $S/packaging/rpm/admin.toml %{buildroot}%{_sysconfdir}/openvibes/admin.toml
install -D -m 0644 $S/packaging/rpm/openvibes-operators.polkit.rules %{buildroot}%{_datadir}/polkit-1/rules.d/50-openvibes-operators.rules
install -D -m 0440 $S/packaging/rpm/openvibes-operators.sudoers %{buildroot}%{_sysconfdir}/sudoers.d/openvibes-operators
install -d -m 0700 %{buildroot}%{_sharedstatedir}/openvibes-ingest
for n in admin ingest distribution vulns; do
    install -D -m 0755 $S/packaging/rpm/rename-account.sh %{buildroot}%{_libexecdir}/openvibes/rename-account-$n
done
install -d -m 0755 %{buildroot}%{_sysconfdir}/openvibes/tls %{buildroot}%{_sysconfdir}/openvibes/pki
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-ingest/LICENSE
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-admin/LICENSE
%if %{with llm}
install -D -m 0755 $S/target/llama/cpu/llama-server %{buildroot}%{_libexecdir}/openvibes-llm/llama-server
install -D -m 0755 $S/target/release/openvibes-llm-check %{buildroot}%{_libexecdir}/openvibes-llm/openvibes-llm-check
install -D -m 0644 $S/packaging/rpm/openvibes-llm.service %{buildroot}%{_unitdir}/openvibes-llm.service
install -D -m 0644 $S/packaging/rpm/openvibes-llm.socket %{buildroot}%{_unitdir}/openvibes-llm.socket
install -D -m 0644 $S/packaging/rpm/openvibes-llm-proxy.service %{buildroot}%{_unitdir}/openvibes-llm-proxy.service
install -D -m 0644 $S/packaging/rpm/openvibes-llm-tune.service %{buildroot}%{_unitdir}/openvibes-llm-tune.service
install -D -m 0644 $S/packaging/rpm/openvibes-llm-model-fetch.service %{buildroot}%{_unitdir}/openvibes-llm-model-fetch.service
install -D -m 0644 $S/packaging/rpm/openvibes-llm.sysusers %{buildroot}%{_sysusersdir}/openvibes-llm.conf
install -D -m 0644 $S/packaging/llm/openvibes-llm.cil %{buildroot}%{_datadir}/selinux/packages/targeted/openvibes-llm.cil
install -D -m 0644 $S/packaging/rpm/llm.conf %{buildroot}%{_sysconfdir}/openvibes/llm.conf
install -d -m 0755 %{buildroot}%{_sharedstatedir}/openvibes-llm/models
touch %{buildroot}%{_sysconfdir}/openvibes/llm-api-key
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-llm/LICENSE
install -D -m 0644 $S/target/llama/LICENSE.llama.cpp %{buildroot}%{_licensedir}/openvibes-llm/LICENSE.llama.cpp
. $S/packaging/llm/model.pin
install -D -m 0644 $S/packaging/llm/model.pin %{buildroot}%{_datadir}/openvibes-llm/model.pin
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-llm-model/LICENSE
# model.conf is written by %%post on a fresh install, then only by Setup and
# the model switch (#264): a package never rewrites it under a running model.
touch %{buildroot}%{_sharedstatedir}/openvibes-llm/model.conf
# The pinned file and every earlier one stay owned, so an upgrade never
# deletes the model in use; the switch removes the old one after.
echo "%ghost %attr(0444, root, root) %{_sharedstatedir}/openvibes-llm/models/$LLM_MODEL_FILE" > model-files.list
grep -v '^#' $S/packaging/llm/past-models | while read -r past; do
    [ -n "$past" ] && echo "%ghost %attr(0444, root, root) %{_sharedstatedir}/openvibes-llm/models/$past"
done >> model-files.list
%if %{with vulkan}
install -D -m 0755 $S/target/llama/vulkan/llama-server %{buildroot}%{_libexecdir}/openvibes-llm/llama-server-vulkan
install -D -m 0644 $S/packaging/rpm/openvibes-llm-vulkan.conf %{buildroot}%{_unitdir}/openvibes-llm.service.d/vulkan.conf
%endif
%endif

%pre -n openvibes-ingest
%rename_pre ingest openvibes-ingest.service
%post -n openvibes-ingest
%{_libexecdir}/openvibes/rename-account-ingest post ingest %{_sysconfdir}/openvibes/ingest.toml
%systemd_post openvibes-ingest.service
%posttrans -n openvibes-ingest
%restart_renamed openvibes-ingest.service
%preun -n openvibes-ingest
%systemd_preun openvibes-ingest.service
%postun -n openvibes-ingest
%systemd_postun_with_restart openvibes-ingest.service

%pre -n openvibes-distribution
%rename_pre distribution openvibes-distribution.service
%post -n openvibes-distribution
%{_libexecdir}/openvibes/rename-account-distribution post distribution %{_sysconfdir}/openvibes/distribution.toml
%systemd_post openvibes-distribution.service
%posttrans -n openvibes-distribution
%restart_renamed openvibes-distribution.service
%preun -n openvibes-distribution
%systemd_preun openvibes-distribution.service
%postun -n openvibes-distribution
%systemd_postun_with_restart openvibes-distribution.service

%post -n openvibes-signer
%systemd_post openvibes-signer.service
%preun -n openvibes-signer
%systemd_preun openvibes-signer.service
%postun -n openvibes-signer
%systemd_postun_with_restart openvibes-signer.service

%pre -n openvibes-vulns
%rename_pre vulns openvibes-vulns.service
%post -n openvibes-vulns
%{_libexecdir}/openvibes/rename-account-vulns post vulns %{_sysconfdir}/openvibes/vulns.toml
%systemd_post openvibes-vulns.service
%posttrans -n openvibes-vulns
%restart_renamed openvibes-vulns.service
%preun -n openvibes-vulns
%systemd_preun openvibes-vulns.service
%postun -n openvibes-vulns
%systemd_postun_with_restart openvibes-vulns.service

%pre -n openvibes-admin
%rename_pre admin openvibes-maintenance.service openvibes-maintenance.timer
%post -n openvibes-admin
%{_libexecdir}/openvibes/rename-account-admin post admin %{_sysconfdir}/openvibes/admin.toml
%systemd_post openvibes-maintenance.timer
%posttrans -n openvibes-admin
%restart_renamed openvibes-maintenance.service openvibes-maintenance.timer
# Before v0.2.7 Setup's agent.toml for the local agent listed collectors
# without services: add it to that exact line only (one log line, never fails).
%{_bindir}/openvibes-admin helper agent-config-upgrade || :
%preun -n openvibes-admin
%systemd_preun openvibes-maintenance.timer
%postun -n openvibes-admin
%systemd_postun openvibes-maintenance.timer
# A new or upgraded rules package is published after the whole transaction,
# by the new admin binary (the unit skips unless Setup ran and is idle).
# Priority below systemd's restart trigger; the unit also waits for migrate.
%transfiletriggerin -P 900000 -n openvibes-admin -- %{_datadir}/openvibes/rules
systemctl start --no-block openvibes-rules-apply.service >/dev/null 2>&1 || :
# The same for an agent installed or upgraded in a later transaction (it
# may only now know the services collector).
%transfiletriggerin -n openvibes-admin -- %{_bindir}/openvibes-agent
%{_bindir}/openvibes-admin helper agent-config-upgrade || :

%if %{with llm}
%pre -n openvibes-llm
%rename_pre llm openvibes-llm.service
%post -n openvibes-llm
# Before any unit (re)start below, in %%posttrans or in the old package's
# %%postun: without it the socket cannot bind 18430 and the proxy cannot
# reach the server under enforcing SELinux. Priority 200: Fedora's for
# modules shipped by packages. As Fedora's %%selinux_modules_install: into
# the targeted store whenever it is the configured policy, enabled or not
# (a host that enables SELinux later has it), and loaded only if enabled.
# Not fatal: the platform works without the assistant.
if [ -e /etc/selinux/config ] && (. /etc/selinux/config && [ "$SELINUXTYPE" = targeted ]); then
    { semodule -n -s targeted -X 200 -i %{_datadir}/selinux/packages/targeted/openvibes-llm.cil &&
        { ! selinuxenabled || load_policy; }; } ||
        echo "openvibes-llm: the SELinux module openvibes-llm could not be installed or loaded; under enforcing SELinux the assistant cannot start" >&2
fi
%systemd_post openvibes-llm.socket openvibes-llm-proxy.service openvibes-llm.service
# The API key the console sends: generated once, root's only. The console
# and openvibes-llm each receive it as a systemd credential.
if [ ! -s %{_sysconfdir}/openvibes/llm-api-key ]; then
    (umask 077 && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > %{_sysconfdir}/openvibes/llm-api-key)
fi
%posttrans -n openvibes-llm
# Upgrade from the always-on server, which was enabled and held 18430: the
# socket takes over the port and the boot start, and starts the server only
# while it is used. The new unit has no [Install], so only an old enable
# leaves it "enabled" (not -q: a unit without [Install] is "static", exit 0):
# this runs once. Stop the old server first so the socket can bind; what
# %%rename_pre stopped is now started by the socket.
if [ "$(systemctl is-enabled openvibes-llm.service 2>/dev/null)" = enabled ]; then
    rm -f /run/openvibes-restart-openvibes-llm.service
    systemctl daemon-reload
    systemctl disable -q openvibes-llm.service || :
    systemctl stop openvibes-llm.service || :
    systemctl enable -q --now openvibes-llm.socket || :
    systemctl is-active -q openvibes-llm.socket ||
        echo "openvibes-llm: openvibes-llm.socket did not start, so the assistant is unavailable; the reason is in the journal (openvibes-llm.socket) and on the Health screen of openvibes-admin" >&2
fi
# An old server that ran but was not enabled (and whose account was renamed)
# is started here once; with StopWhenUnneeded= and no proxy it stops again at
# once. Accepted: it was not meant to run at boot either.
%restart_renamed openvibes-llm.service
# The assistant tunes itself after an install or upgrade: a file trigger
# after the %%posttrans scriptlets and systemd's restart (see below).
%transfiletriggerin -P 900000 -n openvibes-llm -- %{_libexecdir}/openvibes-llm
systemctl start --no-block openvibes-llm-tune.service >/dev/null 2>&1 || :
%preun -n openvibes-llm
%systemd_preun openvibes-llm.socket openvibes-llm-proxy.service openvibes-llm.service
%postun -n openvibes-llm
# Not the socket: a running proxy holds its fd. Restarting the proxy and the
# server (try-restart: only if running) reloads the model on the new files;
# the socket keeps 18430 throughout. `systemctl restart openvibes-llm.socket`
# would restart all three (PartOf=).
%systemd_postun openvibes-llm.socket
%systemd_postun_with_restart openvibes-llm-proxy.service openvibes-llm.service
# Erase only: an upgrade keeps (and its %%post reloads) the module.
if [ $1 -eq 0 ] && [ -e /etc/selinux/config ] && (. /etc/selinux/config && [ "$SELINUXTYPE" = targeted ]); then
    semodule -n -s targeted -X 200 -r openvibes-llm >/dev/null 2>&1 || :
    selinuxenabled && load_policy || :
fi
%endif

%files -n openvibes-ingest
%license %{_licensedir}/openvibes-ingest/LICENSE
%{_bindir}/openvibes-ingest
%{_unitdir}/openvibes-ingest.service
%{_sysusersdir}/openvibes-ingest.conf
%dir %{_libexecdir}/openvibes
%{_libexecdir}/openvibes/rename-account-ingest
%dir %{_sysconfdir}/openvibes
%dir %{_sysconfdir}/openvibes/tls
%dir %{_sysconfdir}/openvibes/pki
%config(noreplace) %attr(0640, root, openvibes-ingest) %{_sysconfdir}/openvibes/ingest.toml
%dir %attr(0700, openvibes-ingest, openvibes-ingest) %{_sharedstatedir}/openvibes-ingest

%files -n openvibes-distribution
%license %{_licensedir}/openvibes-distribution/LICENSE
%{_bindir}/openvibes-distribution
%{_unitdir}/openvibes-distribution.service
%{_sysusersdir}/openvibes-distribution.conf
%dir %{_libexecdir}/openvibes
%{_libexecdir}/openvibes/rename-account-distribution
%dir %{_sysconfdir}/openvibes
%dir %{_sysconfdir}/openvibes/tls
%dir %{_sysconfdir}/openvibes/pki
%config(noreplace) %attr(0640, root, openvibes-distribution) %{_sysconfdir}/openvibes/distribution.toml

%files -n openvibes-signer
%license %{_licensedir}/openvibes-signer/LICENSE
%{_bindir}/openvibes-signer
%{_unitdir}/openvibes-signer.service
%{_sysusersdir}/openvibes-signer.conf
%dir %{_sysconfdir}/openvibes
%config(noreplace) %attr(0640, root, openvibes-signer-clients) %{_sysconfdir}/openvibes/signer.toml
# setgid: status.json takes the operators' group; the key and versions are 0600.
%dir %attr(2750, openvibes-signer, openvibes-operators) %{_sharedstatedir}/openvibes-signer

%files -n openvibes-vulns
%license %{_licensedir}/openvibes-vulns/LICENSE
%{_bindir}/openvibes-vulns
%{_unitdir}/openvibes-vulns.service
%{_sysusersdir}/openvibes-vulns.conf
%dir %{_libexecdir}/openvibes
%{_libexecdir}/openvibes/rename-account-vulns
%dir %{_sysconfdir}/openvibes
%config(noreplace) %attr(0640, root, openvibes-vulns) %{_sysconfdir}/openvibes/vulns.toml

%files -n openvibes-admin
%license %{_licensedir}/openvibes-admin/LICENSE
%{_bindir}/openvibes-admin
%{_unitdir}/openvibes-maintenance.service
%{_unitdir}/openvibes-maintenance.timer
%{_unitdir}/openvibes-migrate.service
%{_unitdir}/openvibes-rules-apply.service
%{_sysusersdir}/openvibes-admin.conf
%dir %{_libexecdir}/openvibes
%{_libexecdir}/openvibes/rename-account-admin
%dir %{_sysconfdir}/openvibes
%config(noreplace) %attr(0640, root, openvibes-admin) %{_sysconfdir}/openvibes/admin.toml
%{_datadir}/polkit-1/rules.d/50-openvibes-operators.rules
%config(noreplace) %attr(0440, root, root) %{_sysconfdir}/sudoers.d/openvibes-operators

%if %{with llm}
%files -n openvibes-llm
%license %{_licensedir}/openvibes-llm/LICENSE
%license %{_licensedir}/openvibes-llm/LICENSE.llama.cpp
%dir %{_libexecdir}/openvibes-llm
%{_libexecdir}/openvibes-llm/llama-server
%{_libexecdir}/openvibes-llm/openvibes-llm-check
%dir %{_datadir}/openvibes-llm
%{_datadir}/openvibes-llm/model.pin
%{_unitdir}/openvibes-llm.service
%{_unitdir}/openvibes-llm.socket
%{_unitdir}/openvibes-llm-proxy.service
%{_unitdir}/openvibes-llm-tune.service
%{_unitdir}/openvibes-llm-model-fetch.service
%{_sysusersdir}/openvibes-llm.conf
%{_datadir}/selinux/packages/targeted/openvibes-llm.cil
%dir %{_sysconfdir}/openvibes
%config(noreplace) %attr(0644, root, root) %{_sysconfdir}/openvibes/llm.conf
%ghost %config(noreplace) %attr(0600, root, root) %{_sysconfdir}/openvibes/llm-api-key
%dir %attr(0775, root, openvibes-admin) %{_sharedstatedir}/openvibes-llm
%dir %attr(0775, root, openvibes-admin) %{_sharedstatedir}/openvibes-llm/models
%ghost %attr(0644, root, root) %{_sharedstatedir}/openvibes-llm/tuning.conf
%ghost %attr(0644, root, root) %{_sharedstatedir}/openvibes-llm/tune.json
%ghost %attr(0600, root, root) %{_sharedstatedir}/openvibes-llm/tune.lock

%files -n openvibes-llm-model -f model-files.list
%license %{_licensedir}/openvibes-llm-model/LICENSE
%ghost %config(noreplace) %attr(0644, root, root) %{_sharedstatedir}/openvibes-llm/model.conf

%post -n openvibes-llm-model
if [ ! -e %{_sharedstatedir}/openvibes-llm/model.conf ]; then
    . %{_datadir}/openvibes-llm/model.pin
    printf 'OPENVIBES_LLM_MODEL=%s\nOPENVIBES_LLM_MODEL_SHA256=%s\nOPENVIBES_LLM_ALIAS=%s\n' \
        "%{_sharedstatedir}/openvibes-llm/models/$LLM_MODEL_FILE" "$LLM_MODEL_SHA256" "$LLM_MODEL_ALIAS" \
        > %{_sharedstatedir}/openvibes-llm/model.conf
    chmod 0644 %{_sharedstatedir}/openvibes-llm/model.conf
fi

%posttrans -n openvibes-llm-model
. %{_datadir}/openvibes-llm/model.pin
[ -e %{_sharedstatedir}/openvibes-llm/models/"$LLM_MODEL_FILE" ] || echo "openvibes-llm-model: the assistant's model is not installed; turn the assistant on in openvibes-admin Setup to download it (offline: see the offline install guide)" >&2

%if %{with vulkan}
%files -n openvibes-llm-vulkan
%{_libexecdir}/openvibes-llm/llama-server-vulkan
%dir %{_unitdir}/openvibes-llm.service.d
%{_unitdir}/openvibes-llm.service.d/vulkan.conf
%endif
%endif

%changelog
* Thu Sep 24 2026 itismelime <26064407+itismelime@users.noreply.github.com> - 0.1.0-1
- openvibes-llm (optional): pinned llama-server for the console's assistant,
  with openvibes-llm-vulkan for GPUs (built with --with vulkan).
- First package: openvibes-ingest, openvibes-distribution (rule bundles for
  agents, port 18424), openvibes-vulns (vulnerability feeds and matching),
  and openvibes-admin.
