# Binary package. The build script prepares the embedded UI from the pinned,
# separately supplied npm cache and builds the release executable first.
%global debug_package %{nil}

Name:           openvibes-console
Version:        %{ov_version}
# Release builds use 1; CI builds pass ov_release=1.1.ci<run>, which sorts
# above the published 0.x.y-1 and below the next version, so a test
# install never looks identical to the published package (board #88).
Release:        %{?ov_release}%{!?ov_release:1}%{?dist}
Summary:        OpenVIBES web console
License:        Apache-2.0
URL:            https://github.com/openvibes-project/openvibes-platform
BuildRequires:  systemd-rpm-macros
%{?systemd_requires}
Source0:        %{console_npm_cache_name}

%description
Self-hosted web console for OpenVIBES platform administration and analysis.

%prep
# The validated source cache is consumed by scripts/build-console-rpm.sh.

%build

%check
printf '%s  %{SOURCE0}\n' '%{console_npm_cache_sha256}' | sha256sum --check --status

%install
S=%{console_repo_root}
install -D -m 0755 $S/target/release/openvibes-console %{buildroot}%{_bindir}/openvibes-console
install -D -m 0644 $S/packaging/rpm/openvibes-console.service %{buildroot}%{_unitdir}/openvibes-console.service
install -D -m 0644 $S/packaging/rpm/openvibes-console.sysusers %{buildroot}%{_sysusersdir}/openvibes-console.conf
install -D -m 0644 $S/packaging/rpm/openvibes-console.preset %{buildroot}%{_prefix}/lib/systemd/system-preset/90-openvibes-console.preset
install -D -m 0640 $S/packaging/rpm/console.toml %{buildroot}%{_sysconfdir}/openvibes/console.toml
install -D -m 0644 $S/LICENSE %{buildroot}%{_licensedir}/openvibes-console/LICENSE
install -D -m 0644 $S/NOTICE %{buildroot}%{_licensedir}/openvibes-console/NOTICE
install -d -m 0700 %{buildroot}%{_sharedstatedir}/openvibes-console
install -d -m 0755 %{buildroot}%{_sysconfdir}/openvibes/tls

%post
%systemd_post openvibes-console.service
%preun
%systemd_preun openvibes-console.service
%postun
%systemd_postun_with_restart openvibes-console.service

%files
%license %{_licensedir}/openvibes-console/LICENSE
%license %{_licensedir}/openvibes-console/NOTICE
%{_bindir}/openvibes-console
%{_unitdir}/openvibes-console.service
%{_sysusersdir}/openvibes-console.conf
%{_prefix}/lib/systemd/system-preset/90-openvibes-console.preset
%dir %{_sysconfdir}/openvibes
%dir %{_sysconfdir}/openvibes/tls
%config(noreplace) %attr(0640, root, openvibes-console) %{_sysconfdir}/openvibes/console.toml
%dir %attr(0700, openvibes-console, openvibes-console) %{_sharedstatedir}/openvibes-console

%changelog
* Fri Sep 25 2026 itismelime <26064407+itismelime@users.noreply.github.com> - 0.1.0-1
- Add the hardened OpenVIBES web console service package.
