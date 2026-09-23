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
  (on SIGINT ingest stops accepting, lets requests in flight finish, bounded
  by `request_timeout_seconds`, then exits). Hardening: `NoNewPrivileges`,
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

Run as root. `openvibes-admin` connects as the OS user `openvibes_admin`
(peer authentication), so every database command runs through
`sudo -u openvibes_admin`; CA material is staged in a directory that user
owns and installed by root afterwards.

1. PostgreSQL: `dnf install postgresql-server`, `postgresql-setup --initdb`,
   `systemctl enable --now postgresql`.
2. `dnf install openvibes-ingest-*.rpm openvibes-admin-*.rpm` (creates the
   users), then the database and schema:

   ```sh
   sudo -u postgres createuser --createrole openvibes_admin
   sudo -u postgres createdb -O openvibes_admin openvibes
   sudo -u openvibes_admin openvibes-admin migrate       # creates the openvibes_ingest role
   sudo -u openvibes_admin openvibes-admin maintenance
   ```

3. CA ([openvibes-admin.md](openvibes-admin.md)). The root lives on an
   offline machine (`openvibes-admin ca init-root --out root`). On this host:

   ```sh
   S=/var/tmp/openvibes-ca
   install -d -o openvibes_admin -g openvibes_admin -m 0700 $S
   sudo -u openvibes_admin openvibes-admin ca intermediate-request --out $S/int
   # offline: ca sign-intermediate --root root --csr intermediate.csr --out intermediate.crt
   # bring intermediate.crt and root/root.crt back into $S/int (owner openvibes_admin)
   sudo -u openvibes_admin openvibes-admin ca import-intermediate \
       --cert $S/int/intermediate.crt --key $S/int/intermediate.key --root-cert $S/int/root.crt
   sudo -u openvibes_admin openvibes-admin ca issue-server ingest.example.com --san 10.0.0.5 \
       --issuer-cert $S/int/intermediate.crt --issuer-key $S/int/intermediate.key --out $S/tls
   ```

4. Install the files where ingest reads them, then remove the staging copies:

   ```sh
   install -m 0644 $S/int/intermediate.crt /etc/openvibes/pki/intermediate.crt
   install -o openvibes_ingest -g openvibes_ingest -m 0600 $S/int/intermediate.key /var/lib/openvibes-ingest/intermediate.key
   install -m 0644 $S/tls/ingest.example.com.crt /etc/openvibes/tls/ingest.crt
   install -o openvibes_ingest -g openvibes_ingest -m 0600 $S/tls/ingest.example.com.key /etc/openvibes/tls/ingest.key
   shred -u $S/int/intermediate.key $S/tls/ingest.example.com.key && rm -r $S
   ```

5. Review `/etc/openvibes/ingest.toml` (the defaults match the paths above),
   then `systemctl enable --now openvibes-ingest openvibes-maintenance.timer`
   and `firewall-cmd --permanent --add-port=18423/tcp && firewall-cmd --reload`.
6. Check: `curl http://127.0.0.1:18480/ready` → 200.

Agents trust `root.crt` (their `platform_ca_file`).

## Renewing the server certificate

It lasts 90 days. Before it expires, stage a copy of the intermediate key for
the admin user, issue, install, and restart:

```sh
S=/var/tmp/openvibes-ca
install -d -o openvibes_admin -g openvibes_admin -m 0700 $S
install -o openvibes_admin -m 0600 /var/lib/openvibes-ingest/intermediate.key $S/intermediate.key
sudo -u openvibes_admin openvibes-admin ca issue-server ingest.example.com --san 10.0.0.5 \
    --issuer-cert /etc/openvibes/pki/intermediate.crt --issuer-key $S/intermediate.key --out $S/tls
install -m 0644 $S/tls/ingest.example.com.crt /etc/openvibes/tls/ingest.crt
install -o openvibes_ingest -g openvibes_ingest -m 0600 $S/tls/ingest.example.com.key /etc/openvibes/tls/ingest.key
shred -u $S/intermediate.key $S/tls/ingest.example.com.key && rm -r $S
systemctl restart openvibes-ingest   # drains requests in flight first
```

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
