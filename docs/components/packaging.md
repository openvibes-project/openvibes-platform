# packaging (RPM)

`packaging/rpm/` builds three Fedora packages from one spec,
`openvibes-platform.spec`: **openvibes-ingest**, **openvibes-distribution**,
and **openvibes-admin**.
`scripts/build-rpm.sh` compiles the release binaries (with
`rust-toolchain.toml` under rustup; CI uses Fedora's own `cargo`) and wraps
them (`rpmbuild -bb`); the spec only installs files. The RPMs are for
deployment, not for inclusion in Fedora itself.

The web console has a separate `openvibes-console.spec` because its embedded
frontend is built from a distinct, checksummed npm cache artefact. Build it
with `scripts/build-console-rpm.sh CACHE_ARCHIVE EXPECTED_SHA256`; the expected
digest must come from trusted release/source metadata independently of the
archive and its checksum sidecar. The script verifies the cache, builds npm
without network access, builds Cargo offline, and passes the cache as RPM
`Source0`. The console unit ships disabled until the operator configures its
database and TLS certificate.

```sh
scripts/build-rpm.sh     # → target/rpm/RPMS/x86_64/openvibes-{ingest,distribution,admin}-*.rpm
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
| `/usr/bin/openvibes-distribution` | 0755 root | distribution |
| `/usr/lib/systemd/system/openvibes-distribution.service` | 0644 root | distribution |
| `/usr/lib/sysusers.d/openvibes-distribution.conf` | user `openvibes_distribution` | distribution |
| `/etc/openvibes/distribution.toml` | 0640 root:openvibes_distribution, `%config(noreplace)` | distribution |
| `/usr/bin/openvibes-admin` | 0755 root | admin |
| `/usr/lib/systemd/system/openvibes-maintenance.{service,timer}` | 0644 root | admin |
| `/usr/lib/sysusers.d/openvibes-admin.conf` | user `openvibes_admin` | admin |
| `/etc/openvibes/admin.toml` | 0640 root:openvibes_admin, `%config(noreplace)` | admin |
| `/usr/bin/openvibes-console` | 0755 root | console |
| `/usr/lib/systemd/system/openvibes-console.service` | 0644 root | console |
| `/usr/lib/sysusers.d/openvibes-console.conf` | user `openvibes_console` | console |
| `/etc/openvibes/console.toml` | 0640 root:openvibes_console, `%config(noreplace)` | console |
| `/var/lib/openvibes-console/` | 0700 openvibes_console | console |

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
- `openvibes-distribution.service`: the same unit and hardening as ingest,
  as `openvibes_distribution`; it writes nothing, so it has no state
  directory.
- `openvibes-maintenance.timer` → `openvibes-maintenance.service`: daily
  (randomized within one hour, catches up after downtime) runs
  `openvibes-admin maintenance` as `openvibes_admin`, with the same hardening.
- `openvibes-console.service`: runs as `openvibes_console`, with the same
  systemd sandbox. It has only `CAP_NET_BIND_SERVICE` to bind the configured
  HTTPS listener on port 443. It is disabled by the package preset until
  configuration and certificate setup are complete.

## First install on Fedora

Run as root. `openvibes-admin` connects as the OS user `openvibes_admin`
(peer authentication), so every database command runs through
`sudo -u openvibes_admin`; CA material is staged in a directory that user
owns and installed by root afterwards. Staging is in `/run`, a tmpfs, so
key copies stay in memory: `shred` cannot reliably erase a file on
copy-on-write filesystems (btrfs, Fedora's default) or on SSDs.

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
   S=/run/openvibes-ca
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
   rm -r $S   # /run is a tmpfs: the staged key copies never reached disk
   ```

5. Review `/etc/openvibes/ingest.toml` (the defaults match the paths above),
   then `systemctl enable --now openvibes-ingest openvibes-maintenance.timer`
   and `firewall-cmd --permanent --add-port=18423/tcp && firewall-cmd --reload`.
6. Check: `curl http://127.0.0.1:18480/ready` → 200.
7. Distribution (optional, `dnf install openvibes-distribution`): give it
   its own server certificate, issued in step 3 next to ingest's (for
   example `ca issue-server rules.example.com … --out $S/tls`) and installed
   in step 4, before the staging directory is removed:

   ```sh
   install -m 0644 $S/tls/rules.example.com.crt /etc/openvibes/tls/distribution.crt
   install -o openvibes_distribution -g openvibes_distribution -m 0600 $S/tls/rules.example.com.key /etc/openvibes/tls/distribution.key
   ```

   `openvibes-admin migrate` (schema 6) already created its database role.
   Then `systemctl enable --now openvibes-distribution`,
   `firewall-cmd --permanent --add-port=18424/tcp && firewall-cmd --reload`,
   and check `curl http://127.0.0.1:18481/ready` → 200. Trust keys and
   publish bundles with `openvibes-admin rules` ([openvibes-admin.md](openvibes-admin.md));
   agents set `distribution_url` and leave out `bundle_file`.

Agents trust `root.crt` (their `platform_ca_file`).

## Console RPM setup

The console RPM requires the platform database schema to be current through
schema 11; those migrations create the least-privilege PostgreSQL role
`openvibes_console`. Install the console RPM after the platform migrations so
the matching operating-system user and database role can use PostgreSQL peer
authentication. Its unit is disabled at install time.

Install a browser-trusted certificate chain and private key at the paths in
`/etc/openvibes/console.toml`, with owner `root:openvibes_console`, mode 0640,
and the TLS directory searchable by the service. Edit the file to replace
`console.example.invalid` with the canonical HTTPS origin and set the public
listen address. For example, install the chain and key like this:

```sh
install -o root -g openvibes_console -m 0640 console-chain.pem /etc/openvibes/tls/console-chain.pem
install -o root -g openvibes_console -m 0640 console-key.pem /etc/openvibes/tls/console-key.pem
```

Then enable the service and allow the configured public port:

```sh
systemctl enable --now openvibes-console
firewall-cmd --permanent --add-port=443/tcp && firewall-cmd --reload
curl http://127.0.0.1:18482/ready
```

The service uses its narrow bind capability for port 443; it has no database
password or signing-key access. Reverse-proxy deployments should change
`transport_mode` and the trusted loopback proxy list before enabling the unit.
For a local TCP proxy, replace the public listener and transport fields with
the following values, keeping the database URL and canonical HTTPS origin:

```toml
development_listen = "127.0.0.1:8443"
health_listen = "127.0.0.1:18482"
transport_mode = "reverse_proxy"
trusted_proxy_addresses = ["127.0.0.1"]
```

The proxy must connect from an allow-listed loopback address and preserve the
configured `Host` authority. Forwarded headers are ignored. Public TLS
terminates at the proxy; the console sends HSTS and uses the external HTTPS
origin for authentication checks. For a Unix socket, configure
`trusted_proxy_uids` to the numeric UID reported by `id -u <proxy-user>`;
leave `trusted_proxy_addresses` empty. Keep `development_listen` present but
unused. For example, with proxy UID 1001:

```toml
development_listen = "127.0.0.1:0"
transport_mode = "reverse_proxy"
unix_socket_file = "/run/openvibes-console/console.sock"
trusted_proxy_addresses = []
trusted_proxy_uids = [1001]
```

Keep the existing `health_listen`, database URL, and HTTPS `public_origin`.
Add the proxy user to the
`openvibes_console` group so it can traverse the runtime directory and connect
to the mode-0660 socket. The listener verifies the peer UID with kernel
credentials and removes only its own socket inode at shutdown. Keep the health
port loopback-only and expose only the proxy's public HTTPS port in the
firewall.

## Console update and recovery

The console refuses to start unless the database is at its exact supported
schema version. The console RPM does not run migrations, and schema migrations
are forward-only. For an update, take a consistent platform database backup
using the site's PostgreSQL backup procedure, including global role
definitions. Keep a separate protected copy of `/etc/openvibes/console.toml`
and the TLS certificate/key files; the database backup does not contain
those files.

Stop `openvibes-console`, `openvibes-ingest`, `openvibes-distribution`, the
maintenance timer/service, and `openvibes-vulns` if installed before
upgrading. This keeps version-exact
services from restarting against either side of the schema change; in
particular, the console RPM's restart hook must not start the new binary
against the old schema. Upgrade the coordinated platform packages, run
`openvibes-admin migrate` as `openvibes_admin`, then start the previously
active services and confirm the console `/ready` endpoint returns 200. The
console does not modify the schema during startup.

Do not downgrade only the console binary after applying a newer schema: an
older binary can refuse the database or misread newer data. To return to a
previous release, stop platform services, restore the complete pre-upgrade
database and its role definitions, restore the matching console config and
TLS files, install the matching platform packages, and start the services
after PostgreSQL is ready. A database restore can reinstate sessions and
credentials as they existed at the backup time, making post-backup account
disables, password resets, and token revocations disappear. Invalidate
sessions and review, revoke, or rotate credentials whose state may have
changed after the backup before exposing the restored instance.

## Trying the whole system

From an empty Fedora 44 host to agent findings in PostgreSQL, with every
component from its RPM under systemd. `scripts/systemd-e2e.sh` runs exactly
these steps (in a podman container with systemd as PID 1), so they are
tested on every change. CI also supplies the console RPM, configures a
temporary TLS certificate, and checks the HTTPS shell, readiness endpoint,
security headers, and systemd sandbox. For a single test host, the platform
and the agent can share the machine, as below; normally the agent runs on the
endpoints.

1. **Platform:** "First install on Fedora" steps 1–7 above, with
   distribution. On a test host, `issue-server localhost --san 127.0.0.1`
   for ingest and `issue-server rules.localhost --san 127.0.0.1` for
   distribution.
2. **Rules:** on your signing machine, make a key and sign a rule set with
   the agent repository's `sign_bundle` example (`cargo run --example
   sign_bundle -- keygen KEY` prints the public key; `… sign KEY rules.json
   baseline 1 org.rules 30 bundle.json`), then on the platform:

   ```sh
   sudo -u openvibes_admin openvibes-admin rules trust add baseline org.rules PUBLIC_KEY
   sudo -u openvibes_admin openvibes-admin rules publish bundle.json
   ```

3. **Token:** `sudo -u openvibes_admin openvibes-admin token create --expires 1h`
   (add `--uses N` for a fleet).
4. **Agent** (on each endpoint): `dnf install openvibes-agent-*.rpm`, then

   ```sh
   install -m 0644 root.crt /etc/openvibes-agent/platform-ca.crt
   install -o openvibes_agent -g openvibes_agent -m 0600 token /etc/openvibes-agent/token
   ```

   and in `/etc/openvibes-agent/agent.toml` set `platform_url` and
   `distribution_url` (e.g. `https://ingest.example.com` and
   `https://rules.example.com`, the names on their server certificates;
   default ports 18423 and 18424) and the rule set, with no `bundle_file`:

   ```toml
   [[rule_sets]]
   id = "baseline"
   trusted_keys = [{ issuer_key_id = "org.rules", public_key = "PUBLIC_KEY" }]
   ```

   `systemctl enable --now openvibes-agent`.
5. **Check:** `openvibes-admin agent list` shows the agent active;
   `journalctl -u openvibes-distribution` logs a 200 for `/v1/rule-bundle`;
   `psql -d openvibes -c "SELECT rule_id, message FROM findings"` (as
   `openvibes_admin`) lists its findings.

The agent package is documented in the agent repository
(`docs/components/packaging.md`): its sandbox, upgrade, and uninstall.

## Renewing the server certificate

It lasts 90 days. Before it expires, stage a copy of the intermediate key for
the admin user, issue, install, and restart:

```sh
S=/run/openvibes-ca
install -d -o openvibes_admin -g openvibes_admin -m 0700 $S
install -o openvibes_admin -m 0600 /var/lib/openvibes-ingest/intermediate.key $S/intermediate.key
sudo -u openvibes_admin openvibes-admin ca issue-server ingest.example.com --san 10.0.0.5 \
    --issuer-cert /etc/openvibes/pki/intermediate.crt --issuer-key $S/intermediate.key --out $S/tls
install -m 0644 $S/tls/ingest.example.com.crt /etc/openvibes/tls/ingest.crt
install -o openvibes_ingest -g openvibes_ingest -m 0600 $S/tls/ingest.example.com.key /etc/openvibes/tls/ingest.key
rm -r $S   # /run is a tmpfs: the staged key copy never reached disk
systemctl restart openvibes-ingest   # drains requests in flight first
```

## Replacing the intermediate CA

The intermediate lasts 2 years, and every agent certificate it issues expires
no later than it does. Replace it **at least `client_certificate_days` (30
by default) plus a margin before it expires**, with an overlap so agents
never lose authentication:

1. **New intermediate:** `ca intermediate-request` on this host, sign it
   offline with the root, and `ca import-intermediate`, as in the first
   install, staged in `/run`.
2. **Accept both:** make `/etc/openvibes/pki/intermediate.crt`, which
   `client_ca_file` names, a bundle of the **old and new** certificates
   (`cat old.crt new.crt`). Ingest accepts client certificates from either.
3. **Issue from the new one:** install the new key as
   `/var/lib/openvibes-ingest/intermediate.key` and the new certificate as
   the `issuing_certificate_file` (a separate file, for example
   `/etc/openvibes/pki/issuing.crt`, while the bundle is in use). Issue a
   new server certificate from it, then `systemctl restart
   openvibes-ingest`.
4. **Agents move over by themselves:** each renews at two thirds of its
   certificate's lifetime and gets a certificate from the new intermediate.
   `openvibes-admin agent list --offline` shows the ones that did not.
5. **Drop the old one:** once every certificate the old intermediate issued
   has expired (at most `client_certificate_days` after step 3), remove it
   from the bundle and restart.

If the old intermediate is simply overwritten, every agent certificate it
issued fails the TLS handshake at once. Agents treat that as a network
error and retry forever, so each would need a new enrollment token. If
nothing is done at all, every agent certificate expires on the
intermediate's last day.

## Known gaps

- Run as `sudo -u openvibes_admin`, audit entries name the service account
  and, as a hint, the person from `SUDO_USER`; sudo's own log is
  authoritative.
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
four units, that the ingest and distribution units stop with SIGINT (the
signal they drain on; an actual stop is not exercised here), and that the
binaries run and refuse a missing configuration.

CI: the `fedora` job (container `fedora:44`) runs `build-rpm.sh`, builds the
console RPM from its offline npm cache, and builds the agent RPM from the
pinned agent revision. The `systemd-e2e` job runs
`scripts/systemd-e2e.sh` on those RPMs under a real systemd; the integration
test then runs against the installed binaries
([integration-agent.md](integration-agent.md)).
