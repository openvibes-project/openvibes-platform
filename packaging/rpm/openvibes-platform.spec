# Binary packaging: scripts/build-rpm.sh builds the release binaries with
# the pinned toolchain first; this spec only installs them.
%global debug_package %{nil}

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

%changelog
* Thu Sep 24 2026 itismelime <26064407+itismelime@users.noreply.github.com> - 0.1.0-1
- First package: openvibes-ingest, openvibes-distribution (rule bundles for
  agents, port 18424), openvibes-vulns (vulnerability feeds and matching),
  and openvibes-admin.
