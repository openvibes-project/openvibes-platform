# packaging (RPM)

`packaging/rpm/` builds two Fedora packages from one spec,
`openvibes-platform.spec`: **openvibes-ingest** and **openvibes-admin**.
`scripts/build-rpm.sh` compiles the release binaries (with
`rust-toolchain.toml` under rustup; CI uses Fedora's own `cargo`) and wraps
them (`rpmbuild -bb`); the spec only installs files. The RPMs are for
deployment, not for inclusion in Fedora itself.

```sh
scripts/build-rpm.sh     # → target/rpm/RPMS/x86_64/openvibes-{ingest,admin}-*.rpm
```

## Contents

| Path | Mode, owner | Package |
|---|---|---|
| `/usr/bin/openvibes-ingest` | 0755 root | ingest |
| `/usr/lib/systemd/system/openvibes-ingest.service` | 0644 root | ingest |
| `/usr/lib/sysusers.d/openvibes-ingest.conf` | user `openvibes_ingest` | ingest |
| `/etc/openvibes/ingest.toml` | 0640 root:openvibes_ingest, `%config(noreplace)` | ingest |
| `/etc/openvibes/{tls,pki}/` | 0755 root | ingest |
| `/var/lib/openvibes-ingest/` | 0700 openvibes_ingest (intermediate key) | ingest |
| `/usr/bin/openvibes-admin` | 0755 root | admin |
| `/usr/lib/systemd/system/openvibes-maintenance.{service,timer}` | 0644 root | admin |
| `/usr/lib/sysusers.d/openvibes-admin.conf` | user `openvibes_admin` | admin |
| `/etc/openvibes/admin.toml` | 0640 root:openvibes_admin, `%config(noreplace)` | admin |

Edited configs survive upgrades. The service users are named exactly like
the PostgreSQL roles, so Fedora's default `local all all peer`
authentication maps them without an ident map. The RPM creates the state
directory itself, so no tmpfiles.d entry is needed.

## Units

- `openvibes-ingest.service`: runs as `openvibes_ingest`, `Restart=on-failure`,
  `LimitNOFILE=65536` (keep `max_connections` below it), `KillSignal=SIGINT`
  (the binary shuts down gracefully on ctrl-c). Hardening: `NoNewPrivileges`,
  `ProtectSystem=strict` (no writable paths: ingest writes only to
  PostgreSQL), `ProtectHome`, `PrivateTmp`, `PrivateDevices`, kernel and
  cgroup protection, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`,
  `RestrictNamespaces`, `MemoryDenyWriteExecute`, the `@system-service`
  syscall filter without `@privileged @resources`, no capabilities,
  `UMask=0077`.
- `openvibes-maintenance.timer` → `openvibes-maintenance.service`: daily
  (randomized within one hour, catches up after downtime) runs
  `openvibes-admin maintenance` as `openvibes_admin`, with the same hardening.

## First install on Fedora

1. PostgreSQL: `dnf install postgresql-server`, `postgresql-setup --initdb`,
   `systemctl enable --now postgresql`.
2. Database and admin role:
   `sudo -u postgres createuser --createrole openvibes_admin` and
   `sudo -u postgres createdb -O openvibes_admin openvibes`.
3. `dnf install openvibes-ingest-*.rpm openvibes-admin-*.rpm`, then
   `sudo -u openvibes_admin openvibes-admin migrate` (creates the
   `openvibes_ingest` role) and `sudo -u openvibes_admin openvibes-admin maintenance`.
4. CA (see [openvibes-admin.md](openvibes-admin.md)): `ca init-root` on an
   offline machine; `ca intermediate-request` on this host; `ca
   sign-intermediate` offline; then `ca import-intermediate` here. Install
   `intermediate.crt` to `/etc/openvibes/pki/` (0644) and `intermediate.key`
   to `/var/lib/openvibes-ingest/` (0600, owner `openvibes_ingest`).
5. `ca issue-server <dns-name> [--san IP] --out /etc/openvibes/tls`, rename to
   `ingest.crt`/`ingest.key` (or edit `ingest.toml`), and
   `chown openvibes_ingest /etc/openvibes/tls/ingest.key`.
6. Edit `/etc/openvibes/ingest.toml`, then
   `systemctl enable --now openvibes-ingest openvibes-maintenance.timer` and
   `firewall-cmd --permanent --add-port=18423/tcp && firewall-cmd --reload`.
7. Check: `curl http://127.0.0.1:18480/ready` → 200.

## Known gaps

- Run as `sudo -u openvibes_admin`, audit entries name `openvibes_admin`;
  sudo's own log names the human.
- Finding retention is set twice: `finding_retention_days` in `ingest.toml`
  and `maintenance --retention-days` (default 90 in both).

## How to test

```sh
scripts/build-rpm.sh
podman run --rm -v "$PWD:/src:Z" -w /src registry.fedoraproject.org/fedora:44 bash -c \
  'dnf -q -y install systemd && dnf -q -y install target/rpm/RPMS/x86_64/openvibes-*.rpm && bash scripts/check-rpm.sh'
```

`scripts/check-rpm.sh` (as root, after install) checks the users, modes and
owners, the `%config(noreplace)` flags, `systemd-analyze verify` on all
three units, graceful stop, and that both binaries run.

CI: the `fedora` job (container `fedora:44`) runs `build-rpm.sh`, installs
the RPMs, and runs `check-rpm.sh`; the integration test then runs against
the installed binaries ([integration-agent.md](integration-agent.md)).
