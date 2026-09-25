# Binary packaging: scripts/build-rpm.sh builds the release binaries with
# the pinned toolchain first; this spec only installs them.
%global debug_package %{nil}
# openvibes-llm: scripts/build-llama-server.sh builds llama-server first
# (skip with --without llm); the Vulkan variant with --with vulkan.
%bcond llm 1
%bcond vulkan 0

Name:           openvibes-platform
Version:        %{ov_version}
Release:        1%{?dist}
Summary:        OpenVIBES platform services
License:        MIT
URL:            https://github.com/openvibes-project/openvibes-platform
BuildRequires:  systemd-rpm-macros

%description
OpenVIBES platform services.

%package -n openvibes-ingest
Summary:        OpenVIBES agent-facing ingest service
%{?systemd_requires}

%description -n openvibes-ingest
Receives enrollments, renewals, heartbeats, and findings from OpenVIBES agents over mTLS.

%package -n openvibes-distribution
Summary:        OpenVIBES rule distribution service
%{?systemd_requires}

%description -n openvibes-distribution
Serves operator-published, offline-signed rule bundles to enrolled OpenVIBES agents over mTLS.

%package -n openvibes-vulns
Summary:        OpenVIBES vulnerability feeds and matching
%{?systemd_requires}

%description -n openvibes-vulns
Fetches Fedora security advisories and matches them against the package
inventories OpenVIBES agents report.

%package -n openvibes-admin
Summary:        OpenVIBES operator CLI and maintenance timer
%{?systemd_requires}

%description -n openvibes-admin
Schema migration, built-in CA, tokens, agents, and daily partition maintenance.

%if %{with llm}
%package -n openvibes-llm
Summary:        OpenVIBES local model server for the console's assistant
License:        MIT
# Models are installed with openvibes-admin, whose group owns the model store.
Requires:       openvibes-admin = %{version}-%{release}
%{?systemd_requires}

%description -n openvibes-llm
llama.cpp's llama-server from a pinned build (no subprocesses, RPC, TLS, or
web UI), run on loopback as its own sandboxed user with a model file whose
SHA-256 is pinned. Optional: the platform works without it.

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
install -D -m 0755 $S/target/release/openvibes-vulns %{buildroot}%{_bindir}/openvibes-vulns
install -D -m 0644 $S/packaging/rpm/openvibes-vulns.service %{buildroot}%{_unitdir}/openvibes-vulns.service
install -D -m 0644 $S/packaging/rpm/openvibes-vulns.sysusers %{buildroot}%{_sysusersdir}/openvibes-vulns.conf
install -D -m 0640 $S/packaging/rpm/vulns.toml %{buildroot}%{_sysconfdir}/openvibes/vulns.toml
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-vulns/LICENSE
install -D -m 0644 $S/packaging/rpm/openvibes-ingest.service %{buildroot}%{_unitdir}/openvibes-ingest.service
install -D -m 0644 $S/packaging/rpm/openvibes-maintenance.service %{buildroot}%{_unitdir}/openvibes-maintenance.service
install -D -m 0644 $S/packaging/rpm/openvibes-maintenance.timer %{buildroot}%{_unitdir}/openvibes-maintenance.timer
install -D -m 0644 $S/packaging/rpm/openvibes-ingest.sysusers %{buildroot}%{_sysusersdir}/openvibes-ingest.conf
install -D -m 0644 $S/packaging/rpm/openvibes-admin.sysusers %{buildroot}%{_sysusersdir}/openvibes-admin.conf
install -D -m 0640 $S/packaging/rpm/ingest.toml %{buildroot}%{_sysconfdir}/openvibes/ingest.toml
install -D -m 0640 $S/packaging/rpm/admin.toml %{buildroot}%{_sysconfdir}/openvibes/admin.toml
install -d -m 0700 %{buildroot}%{_sharedstatedir}/openvibes-ingest
install -d -m 0755 %{buildroot}%{_sysconfdir}/openvibes/tls %{buildroot}%{_sysconfdir}/openvibes/pki
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-ingest/LICENSE
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-admin/LICENSE
%if %{with llm}
install -D -m 0755 $S/target/llama/cpu/llama-server %{buildroot}%{_libexecdir}/openvibes-llm/llama-server
install -D -m 0755 $S/target/release/openvibes-llm-check %{buildroot}%{_libexecdir}/openvibes-llm/openvibes-llm-check
install -D -m 0644 $S/packaging/rpm/openvibes-llm.service %{buildroot}%{_unitdir}/openvibes-llm.service
install -D -m 0644 $S/packaging/rpm/openvibes-llm.sysusers %{buildroot}%{_sysusersdir}/openvibes-llm.conf
install -D -m 0644 $S/packaging/rpm/llm.conf %{buildroot}%{_sysconfdir}/openvibes/llm.conf
install -d -m 0755 %{buildroot}%{_sharedstatedir}/openvibes-llm/models
touch %{buildroot}%{_sysconfdir}/openvibes/llm-api-key
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-llm/LICENSE
install -D -m 0644 $S/target/llama/LICENSE.llama.cpp %{buildroot}%{_licensedir}/openvibes-llm/LICENSE.llama.cpp
%if %{with vulkan}
install -D -m 0755 $S/target/llama/vulkan/llama-server %{buildroot}%{_libexecdir}/openvibes-llm/llama-server-vulkan
install -D -m 0644 $S/packaging/rpm/openvibes-llm-vulkan.conf %{buildroot}%{_unitdir}/openvibes-llm.service.d/vulkan.conf
%endif
%endif

%post -n openvibes-ingest
%systemd_post openvibes-ingest.service
%preun -n openvibes-ingest
%systemd_preun openvibes-ingest.service
%postun -n openvibes-ingest
%systemd_postun_with_restart openvibes-ingest.service

%post -n openvibes-distribution
%systemd_post openvibes-distribution.service
%preun -n openvibes-distribution
%systemd_preun openvibes-distribution.service
%postun -n openvibes-distribution
%systemd_postun_with_restart openvibes-distribution.service

%post -n openvibes-vulns
%systemd_post openvibes-vulns.service
%preun -n openvibes-vulns
%systemd_preun openvibes-vulns.service
%postun -n openvibes-vulns
%systemd_postun_with_restart openvibes-vulns.service

%post -n openvibes-admin
%systemd_post openvibes-maintenance.timer
%preun -n openvibes-admin
%systemd_preun openvibes-maintenance.timer
%postun -n openvibes-admin
%systemd_postun openvibes-maintenance.timer

%if %{with llm}
%post -n openvibes-llm
%systemd_post openvibes-llm.service
# The API key the console sends: generated once, root's only. The console
# and openvibes-llm each receive it as a systemd credential.
if [ ! -s %{_sysconfdir}/openvibes/llm-api-key ]; then
    (umask 077 && head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > %{_sysconfdir}/openvibes/llm-api-key)
fi
%preun -n openvibes-llm
%systemd_preun openvibes-llm.service
%postun -n openvibes-llm
%systemd_postun_with_restart openvibes-llm.service
%endif

%files -n openvibes-ingest
%license %{_licensedir}/openvibes-ingest/LICENSE
%{_bindir}/openvibes-ingest
%{_unitdir}/openvibes-ingest.service
%{_sysusersdir}/openvibes-ingest.conf
%dir %{_sysconfdir}/openvibes
%dir %{_sysconfdir}/openvibes/tls
%dir %{_sysconfdir}/openvibes/pki
%config(noreplace) %attr(0640, root, openvibes_ingest) %{_sysconfdir}/openvibes/ingest.toml
%dir %attr(0700, openvibes_ingest, openvibes_ingest) %{_sharedstatedir}/openvibes-ingest

%files -n openvibes-distribution
%license %{_licensedir}/openvibes-distribution/LICENSE
%{_bindir}/openvibes-distribution
%{_unitdir}/openvibes-distribution.service
%{_sysusersdir}/openvibes-distribution.conf
%dir %{_sysconfdir}/openvibes
%dir %{_sysconfdir}/openvibes/tls
%dir %{_sysconfdir}/openvibes/pki
%config(noreplace) %attr(0640, root, openvibes_distribution) %{_sysconfdir}/openvibes/distribution.toml

%files -n openvibes-vulns
%license %{_licensedir}/openvibes-vulns/LICENSE
%{_bindir}/openvibes-vulns
%{_unitdir}/openvibes-vulns.service
%{_sysusersdir}/openvibes-vulns.conf
%dir %{_sysconfdir}/openvibes
%config(noreplace) %attr(0640, root, openvibes_vulns) %{_sysconfdir}/openvibes/vulns.toml

%files -n openvibes-admin
%license %{_licensedir}/openvibes-admin/LICENSE
%{_bindir}/openvibes-admin
%{_unitdir}/openvibes-maintenance.service
%{_unitdir}/openvibes-maintenance.timer
%{_sysusersdir}/openvibes-admin.conf
%dir %{_sysconfdir}/openvibes
%config(noreplace) %attr(0640, root, openvibes_admin) %{_sysconfdir}/openvibes/admin.toml

%if %{with llm}
%files -n openvibes-llm
%license %{_licensedir}/openvibes-llm/LICENSE
%license %{_licensedir}/openvibes-llm/LICENSE.llama.cpp
%dir %{_libexecdir}/openvibes-llm
%{_libexecdir}/openvibes-llm/llama-server
%{_libexecdir}/openvibes-llm/openvibes-llm-check
%{_unitdir}/openvibes-llm.service
%{_sysusersdir}/openvibes-llm.conf
%dir %{_sysconfdir}/openvibes
%config(noreplace) %attr(0644, root, root) %{_sysconfdir}/openvibes/llm.conf
%ghost %config(noreplace) %attr(0600, root, root) %{_sysconfdir}/openvibes/llm-api-key
%dir %attr(0775, root, openvibes_admin) %{_sharedstatedir}/openvibes-llm
%dir %attr(0775, root, openvibes_admin) %{_sharedstatedir}/openvibes-llm/models

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
