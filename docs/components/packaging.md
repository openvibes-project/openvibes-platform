# packaging (RPM)

`packaging/rpm/` builds Fedora packages from one spec,
`openvibes-platform.spec`: **openvibes-ingest**, **openvibes-distribution**,
**openvibes-vulns**, **openvibes-admin**, and the optional **openvibes-llm**
(the assistant's local model server, [openvibes-llm.md](openvibes-llm.md);
`OV_LLM=0` skips it, `OV_LLM_VULKAN=1` adds **openvibes-llm-vulkan**;
**openvibes-llm-model** carries no model bytes: it selects the pinned model and owns its
path so upgrades keep it; `openvibes-admin assistant model fetch` downloads the model;
`openvibes-llm` recommends the bridge).
`scripts/build-rpm.sh` compiles the release binaries (with
`rust-toolchain.toml` under rustup; CI uses Fedora's own `cargo`) and wraps
them (`rpmbuild -bb`); the spec only installs files. The RPMs are for
deployment, not for inclusion in Fedora itself.

The web console has a separate `openvibes-console.spec` because its embedded
frontend is built from a distinct, checksummed npm cache artefact. Build it
with `scripts/build-console-rpm.sh CACHE_ARCHIVE EXPECTED_SHA256 [RPM_VERSION...]`
(one package per version from one build; default: the workspace version); the expected
digest must come from trusted release/source metadata independently of the
archive and its checksum sidecar. The script verifies the cache, installs npm
dependencies in offline mode (and uses `unshare -rn` when supported to isolate
build scripts), builds Cargo offline, and passes the cache as RPM `Source0`.
The embedded interface is the live-only build of
[console-web](console-web.md): it has no demo data or demo switch. The
console unit ships disabled until the operator configures its
database and TLS certificate.

```sh
scripts/build-rpm.sh     # → target/rpm/RPMS/x86_64/openvibes-{ingest,distribution,vulns,admin,llm}-*.rpm
```

## Contents

| Path | Mode, owner | Package |
|---|---|---|
| `/usr/bin/openvibes-ingest` | 0755 root | ingest |
| `/usr/lib/systemd/system/openvibes-ingest.service` | 0644 root | ingest |
| `/usr/lib/sysusers.d/openvibes-ingest.conf` | user `openvibes-ingest` | ingest |
| `/etc/openvibes/ingest.toml` | 0640 root:openvibes-ingest, `%config(noreplace)` | ingest |
| `/etc/openvibes/{tls,pki}/` | 0755 root | ingest |
| `/var/lib/openvibes-ingest/` | 0700 openvibes-ingest (intermediate key) | ingest |
| `/usr/bin/openvibes-distribution` | 0755 root | distribution |
| `/usr/lib/systemd/system/openvibes-distribution.service` | 0644 root | distribution |
| `/usr/lib/sysusers.d/openvibes-distribution.conf` | user `openvibes-distribution` | distribution |
| `/etc/openvibes/distribution.toml` | 0640 root:openvibes-distribution, `%config(noreplace)` | distribution |
| `/usr/bin/openvibes-vulns` | 0755 root | vulns |
| `/usr/lib/systemd/system/openvibes-vulns.service` | 0644 root | vulns |
| `/usr/lib/sysusers.d/openvibes-vulns.conf` | user `openvibes-vulns` | vulns |
| `/etc/openvibes/vulns.toml` | 0640 root:openvibes-vulns, `%config(noreplace)` | vulns |
| `/usr/bin/openvibes-admin` | 0755 root | admin |
| `/usr/lib/systemd/system/openvibes-maintenance.{service,timer}` | 0644 root | admin |
| `/usr/lib/systemd/system/openvibes-migrate.service` | 0644 root | admin |
| `/usr/lib/systemd/system/openvibes-rules-apply.service` | 0644 root | admin |
| `/usr/lib/sysusers.d/openvibes-admin.conf` | user `openvibes-admin` | admin |
| `/etc/openvibes/admin.toml` | 0640 root:openvibes-admin, `%config(noreplace)` | admin |
| `/usr/bin/openvibes-console` | 0755 root | console |
| `/usr/lib/systemd/system/openvibes-console.service` | 0644 root | console |
| `/usr/lib/sysusers.d/openvibes-console.conf` | user `openvibes-console` | console |
| `/etc/openvibes/console.toml` | 0640 root:openvibes-console, `%config(noreplace)` | console |
| `/var/lib/openvibes-console/` | 0700 openvibes-console | console |
| `/usr/libexec/openvibes-llm/{llama-server,openvibes-llm-check}` | 0755 root | llm |
| `/usr/lib/systemd/system/openvibes-llm.service` | 0644 root | llm |
| `/usr/lib/sysusers.d/openvibes-llm.conf` | user `openvibes-llm` | llm |
| `/etc/openvibes/llm.conf` | 0644 root, `%config(noreplace)` | llm |
| `/etc/openvibes/llm-api-key` | 0600 root, generated at first install | llm |
| `/var/lib/openvibes-llm/{,models/}` | 0775 root:openvibes-admin | llm |
| `/var/lib/openvibes-llm/models/Qwen3.5-4B-Q4_K_M.gguf` and every earlier pinned file in `packaging/llm/past-models` (%ghost, fetched by `assistant model fetch`), `/var/lib/openvibes-llm/model.conf` (%ghost %config noreplace, written by `%post` on a fresh install) | 0444 root; 0644 root | llm-model |
| `/usr/share/openvibes-llm/model.pin` | 0644 root | llm |
| `/usr/bin/openvibes-signer` | 0755 root | signer |
| `/usr/lib/systemd/system/openvibes-signer.service` | 0644 root | signer |
| `/usr/lib/sysusers.d/openvibes-signer.conf` | user `openvibes-signer`, group `openvibes-signer-clients` (the socket's) | signer |
| `/etc/openvibes/signer.toml` | 0640 root:openvibes-signer-clients, `%config(noreplace)` | signer |
| `/var/lib/openvibes-signer/` | 2750 openvibes-signer:openvibes-operators (setgid: `status.json` 0640 reaches operators; `site.key`, `versions.json` and the signed rules are 0600) | signer |

**openvibes-signer** (own rules, board #107) runs as `openvibes-signer`
with `openvibes-signer-clients` as its group, so its socket
(`/run/openvibes-signer/sign.sock`, 0660, in a 0750 runtime directory)
reaches only that group's members: Setup adds `openvibes-console`. The unit
has no network (`PrivateNetwork=yes`, `AF_UNIX` only), no capabilities, and
writes only its state directory. It refuses to sign until `openvibes-signer
seed --min-version N` (run as `openvibes-signer`, group
`openvibes-signer-clients`) has created the site key and version state;
Setup does this. It needs `openvibes-admin` for the operators group.

Edited configs survive upgrades. The service users are named exactly like
the PostgreSQL roles, so Fedora's default `local all all peer`
authentication maps them without an ident map. The RPM creates the state
directory itself, so no tmpfiles.d entry is needed.

## Units

- `openvibes-ingest.service`: runs as `openvibes-ingest`, `Restart=on-failure`,
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
  as `openvibes-distribution`; it writes nothing, so it has no state
  directory.
- `openvibes-vulns.service`: the same unit and hardening, as
  `openvibes-vulns`; it connects out to its feeds (or `proxy_url`) and
  writes to PostgreSQL and its state directory `/var/lib/openvibes-vulns`
  (0700, `StateDirectory`), where OSV downloads (Ubuntu's is ~760 MB) stay
  only until imported. On SIGINT it stops; an interrupted feed
  check is redone at the next start.
- `openvibes-migrate.service` (admin package, #77): a oneshot, as
  `openvibes-admin` with the same hardening, running `openvibes-admin
  migrate --additive` once Setup has run (`setup.toml` exists). Ingest,
  distribution, vulns, the console and maintenance want it and start after
  it, so the restart after a plain `dnf upgrade` migrates first. A migration
  that changes stored data (e.g. migration 43) is done by the unit itself
  (`helper upgrade-migrate`, its only `ExecStart`, run with full
  privileges): it stops the running ingest, distribution, vulns, signer,
  console and maintenance units, backs up to
  `/var/backups/openvibes/upgrade-<time>.dump` (with `.roles.sql`; 0700 root
  directory, 0600 files; never pruned, delete old ones yourself; needs
  about twice the dump's size free in `/var` while it copies), migrates and
  publishes a newer rules package, as Update does, then queues the stopped
  units to start (`systemctl start --no-block`, behind this unit). If the
  backup or migration fails, the services are queued to start anyway, the
  unit fails with an "upgrade migration failed" journal line, and a
  half-done-update mark in `/run` makes later runs skip (no new backup
  every few seconds) until Update is run or the host reboots.
- `openvibes-rules-apply.service` (admin package): a oneshot as root, running
  `openvibes-admin helper rules-apply`; no `[Install]`. A
  `%transfiletriggerin -P 900000` on `/usr/share/openvibes/rules` starts it
  (`--no-block`) after any transaction that installs or upgrades files
  there, so new rules are published with no Update or Repair. It skips
  when Setup never ran or is running.
- openvibes-admin's `%posttrans`, and its `%transfiletriggerin` on
  `/usr/bin/openvibes-agent` (an agent installed or upgraded later), run
  `openvibes-admin helper agent-config-upgrade || :`: on a host Setup
  configured before v0.2.7 it adds `services` to the local agent's
  `collectors` line (only the exact line Setup wrote, only for an agent
  rpm reports as 0.2.2 or later) and queues a try-restart of the agent; it
  never fails the transaction.
- `openvibes-llm-tune.service` (llm package): a oneshot as root, running
  `openvibes-admin helper assistant-tune --auto`; no `[Install]`; the
  llm package's `%transfiletriggerin -P 900000` on `/usr/libexec/openvibes-llm` starts it (`--no-block`, after the `%posttrans` scriptlets and the restart). It tunes only an
  untuned host with the assistant on the pinned model.
- `openvibes-maintenance.timer` → `openvibes-maintenance.service`: daily
  (randomized within one hour, catches up after downtime) runs
  `openvibes-admin maintenance` as `openvibes-admin`, with the same hardening.
- `openvibes-console.service`: runs as `openvibes-console`, with the same
  systemd sandbox. It has only `CAP_NET_BIND_SERVICE` to bind the configured
  HTTPS listener on port 443. It is disabled by the package preset until
  configuration and certificate setup are complete.
- `openvibes-llm.service`: `llama-server` on loopback as `openvibes-llm`,
  after `openvibes-llm-check`. It has the same hardening plus
  `IPAddressDeny=any`/`IPAddressAllow=localhost`, `NoExecPaths=/`, the API
  key as a credential, and resource shares
  ([openvibes-llm.md](openvibes-llm.md)).

## First install on Fedora

The quickest path is Setup: `sudo dnf install openvibes-admin`, then run
`openvibes-admin` (the Setup tab) or `sudo openvibes-admin setup --quick
--components … --hostname …` ([openvibes-admin.md](openvibes-admin.md),
"Setup command"); `scripts/systemd-e2e.sh` installs the platform this way.
The steps below are what Setup runs, for hosts set up by hand.

Run as root. `openvibes-admin` connects as the OS user `openvibes-admin`
(peer authentication), so every database command runs through
`sudo -u openvibes-admin`; CA material is staged in a directory that user
owns and installed by root afterwards. Staging is in `/run`, a tmpfs, so
key copies stay in memory: `shred` cannot reliably erase a file on
copy-on-write filesystems (btrfs, Fedora's default) or on SSDs.

1. PostgreSQL: `dnf install postgresql-server`, `postgresql-setup --initdb`,
   `systemctl enable --now postgresql`.
2. `dnf install openvibes-ingest-*.rpm openvibes-admin-*.rpm` (creates the
   users), then the database and schema:

   ```sh
   sudo -u postgres createuser --createrole openvibes-admin
   sudo -u postgres createdb -O openvibes-admin openvibes
   sudo -u openvibes-admin openvibes-admin migrate       # creates the openvibes-ingest role
   sudo -u openvibes-admin openvibes-admin maintenance
   ```

3. CA ([openvibes-admin.md](openvibes-admin.md)). The root lives on an
   offline machine (`openvibes-admin ca init-root --out root`). On this host:

   ```sh
   S=/run/openvibes-ca
   install -d -o openvibes-admin -g openvibes-admin -m 0700 $S
   sudo -u openvibes-admin openvibes-admin ca intermediate-request --out $S/int
   # offline: ca sign-intermediate --root root --csr intermediate.csr --out intermediate.crt
   # bring intermediate.crt and root/root.crt back into $S/int (owner openvibes-admin)
   sudo -u openvibes-admin openvibes-admin ca import-intermediate \
       --cert $S/int/intermediate.crt --key $S/int/intermediate.key --root-cert $S/int/root.crt
   sudo -u openvibes-admin openvibes-admin ca issue-server ingest.example.com --san 10.0.0.5 \
       --issuer-cert $S/int/intermediate.crt --issuer-key $S/int/intermediate.key --out $S/tls
   ```

4. Install the files where ingest reads them, then remove the staging copies:

   ```sh
   install -m 0644 $S/int/intermediate.crt /etc/openvibes/pki/intermediate.crt
   install -o openvibes-ingest -g openvibes-ingest -m 0600 $S/int/intermediate.key /var/lib/openvibes-ingest/intermediate.key
   install -m 0644 $S/tls/ingest.example.com.crt /etc/openvibes/tls/ingest.crt
   install -o openvibes-ingest -g openvibes-ingest -m 0600 $S/tls/ingest.example.com.key /etc/openvibes/tls/ingest.key
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
   install -o openvibes-distribution -g openvibes-distribution -m 0600 $S/tls/rules.example.com.key /etc/openvibes/tls/distribution.key
   ```

   `openvibes-admin migrate` (schema 6) already created its database role.
   Then `systemctl enable --now openvibes-distribution`,
   `firewall-cmd --permanent --add-port=18424/tcp && firewall-cmd --reload`,
   and check `curl http://127.0.0.1:18481/ready` → 200. Trust keys and
   publish bundles with `openvibes-admin rules` ([openvibes-admin.md](openvibes-admin.md));
   agents set `distribution_url` and leave out `bundle_file`.
8. Vulnerabilities (optional, `dnf install openvibes-vulns`): it needs no
   certificate. `openvibes-admin migrate` (schema 8) already created its
   database role. It reaches `mirrors.fedoraproject.org`, `www.cisa.gov`
   (KEV), `epss.empiricalsecurity.com` (EPSS), `services.nvd.nist.gov`
   (NVD), `euvdservices.enisa.europa.eu` (EUVD) and
   `osv-vulnerabilities.storage.googleapis.com` (Debian, Ubuntu, Rocky,
   Alma) over HTTPS; behind a
   proxy set `proxy_url` in `/etc/openvibes/vulns.toml`. An NVD API key
   (free) speeds the first NVD fill from about 95 to 10 minutes: put it in
   `/etc/openvibes/nvd.key`, owned by `openvibes-vulns` with mode 0600
   (a group- or world-readable key is refused), and set
   `nvd_api_key_file`. Without network access, set the five `*_url` keys
   to `""` and import files by hand (`openvibes-admin feeds import FILE
   --source fedora-44-x86_64|kev|epss|nvd|euvd`,
   [openvibes-admin.md](openvibes-admin.md)).
   Then `systemctl enable --now openvibes-vulns` and check
   `curl http://127.0.0.1:18483/ready` → 200; `openvibes-admin feeds
   status` shows each Fedora release your agents report once it is checked.

Agents trust `root.crt` (their `platform_ca_file`).

## Console RPM setup

The console RPM requires the platform database schema to be current through
schema 23; those migrations create the least-privilege PostgreSQL role
`openvibes-console`. Install the console RPM after the platform migrations so
the matching operating-system user and database role can use PostgreSQL peer
authentication. Its unit is disabled at install time.

Install a browser-trusted certificate chain and private key at the paths in
`/etc/openvibes/console.toml`, with owner `root:openvibes-console`, mode 0640,
and the TLS directory searchable by the service. Edit the file to replace
`console.example.invalid` with the canonical HTTPS origin and set the public
listen address. For example, install the chain and key like this:

```sh
install -o root -g openvibes-console -m 0640 console-chain.pem /etc/openvibes/tls/console-chain.pem
install -o root -g openvibes-console -m 0640 console-key.pem /etc/openvibes/tls/console-key.pem
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
configured `Host` authority. For source-address login throttling, the console
uses the last address in `X-Forwarded-For` from an allow-listed proxy. This
supports proxies that append their observed client address to an existing
forwarded chain. The proxy must append the actual peer address; a missing or
malformed final address disables the source-address bucket while the
per-account limit remains.
Public TLS
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
`openvibes-console` group so it can traverse the runtime directory and connect
to the mode-0660 socket. The listener verifies the peer UID with kernel
credentials and removes only its own socket inode at shutdown. Keep the health
port loopback-only and expose only the proxy's public HTTPS port in the
firewall.

## Updating and removing

Update through Setup: the TUI's Setup tab, `u`, or `sudo openvibes-admin
setup --update [--backup PATH]`. It offers a database backup, stops the
running OpenVIBES units, upgrades exactly the installed OpenVIBES packages
(the agent on this host too), migrates, and starts what was running
([openvibes-admin.md](openvibes-admin.md), "Setup command"). A plain OS
update should leave them out (`dnf upgrade --exclude='openvibes-*'`); the
manual procedure is below. Remove through Setup's `x` or `setup
--uninstall --keep-data|--everything`.

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
security headers, and systemd sandbox. It installs a lower-version console
RPM, creates an admin account and browser session, upgrades to the release RPM,
and verifies that config, TLS files, account, active database session, and
authenticated access survive. The RPM install also proves Node.js is not a
runtime dependency. It restarts the console in Unix proxy mode and checks that
an allowed peer UID succeeds while the console's own service UID is rejected.
For a single test host, the platform and the agent
can share the machine, as below; normally the agent runs on the endpoints.

1. **Platform:** "First install on Fedora" steps 1–8 above, with
   distribution and vulns. On a test host, `issue-server localhost --san 127.0.0.1`
   for ingest and `issue-server rules.localhost --san 127.0.0.1` for
   distribution.
2. **Rules:** on your signing machine, make a key and sign a rule set
   (`openvibes-admin rules keygen KEY --rule-set baseline --issuer org.rules`
   prints the trust line; `openvibes-admin rules sign KEY rules.json
   --rule-set baseline --version 1 --issuer org.rules --days 30 -o
   bundle.json`), then on the platform:

   ```sh
   sudo -u openvibes-admin openvibes-admin rules trust add baseline org.rules PUBLIC_KEY
   sudo -u openvibes-admin openvibes-admin rules publish bundle.json
   ```

3. **Token:** `sudo -u openvibes-admin openvibes-admin token create --expires 1h`
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
   `openvibes-admin`) lists its findings; `openvibes-admin vulns list`
   lists the agent's vulnerable packages once its release's feed is in
   (the end-to-end test imports an offline feed that marks the
   container's `bash` as vulnerable, before the agent enrolls, so the
   vulnerability can only open through the service's re-match).

The agent package is documented in the agent repository
(`docs/components/packaging.md`): its sandbox, upgrade, and uninstall.

## Upgrading from `openvibes_*` accounts

Service accounts and their PostgreSQL roles are named with hyphens since
the admin TUI work (`openvibes-admin`, `openvibes-ingest`,
`openvibes-distribution`, `openvibes-vulns`, `openvibes-llm`; before:
`openvibes_admin`, …). Upgrading the RPMs renames an existing install:

- `%pre` stops the unit (and the maintenance timer) and renames the OS user
  and group (`usermod -l`, `groupmod -n`); uids, file ownership and group
  memberships stay the same. If rpm already created the new name from the
  sysusers file, that empty account is removed first. Units that were
  running are started again at the end of the transaction (`%posttrans`).
- If a process still runs as the old user (for example an operator's
  `runuser -u openvibes_admin …`), that package's upgrade is refused with
  its PIDs: `processes still run as openvibes_admin …; stop them and
  upgrade again`. The package stays installed on the old name, consistent
  and running; the other packages upgrade. Run the upgrade again once the
  process has ended.
- `%post` changes `user=openvibes_NAME` to `user=openvibes-NAME` in the kept
  `database_url` of `/etc/openvibes/NAME.toml` (nothing else in the file),
  then renames the PostgreSQL role as `postgres`
  (`ALTER ROLE openvibes_ingest RENAME TO "openvibes-ingest"`); ownership and
  grants move with it.
- If PostgreSQL is not reachable on this host (a remote database, or it was
  stopped), the upgrade still completes and prints the statements to run
  there as `postgres`:

  ```sql
  ALTER ROLE openvibes_admin RENAME TO "openvibes-admin";
  ALTER ROLE openvibes_ingest RENAME TO "openvibes-ingest";
  ALTER ROLE openvibes_distribution RENAME TO "openvibes-distribution";
  ALTER ROLE openvibes_vulns RENAME TO "openvibes-vulns";
  ```

  On a fresh install PostgreSQL is not on the host yet (Setup installs it)
  and the config points at the local socket: there is no role to rename,
  so nothing is printed (install walkthrough, 2026-10-08, where the message
  alarmed a new user).

`%post` only changes the config and the role once the OS account was
renamed, and warns when the roles are not as expected (neither name, or
both). Every step checks first, so reinstalling changes nothing. In SQL the new
names need quotes (`GRANT … TO "openvibes-ingest"`).

## Renewing the server certificate

It lasts 90 days. Before it expires, stage a copy of the intermediate key for
the admin user, issue, install, and restart:

```sh
S=/run/openvibes-ca
install -d -o openvibes-admin -g openvibes-admin -m 0700 $S
install -o openvibes-admin -m 0600 /var/lib/openvibes-ingest/intermediate.key $S/intermediate.key
sudo -u openvibes-admin openvibes-admin ca issue-server ingest.example.com --san 10.0.0.5 \
    --issuer-cert /etc/openvibes/pki/intermediate.crt --issuer-key $S/intermediate.key --out $S/tls
install -m 0644 $S/tls/ingest.example.com.crt /etc/openvibes/tls/ingest.crt
install -o openvibes-ingest -g openvibes-ingest -m 0600 $S/tls/ingest.example.com.key /etc/openvibes/tls/ingest.key
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

## Releases

A tag `vX.Y.Z` equal to the workspace version runs `.github/workflows/release.yml`
(admins only create tags): the RPMs are built in `fedora:44`, signed with the
OpenVIBES package key (organisation secrets `RPM_SIGNING_KEY`,
`RPM_SIGNING_PASSPHRASE`), and checked against the committed public key
`packaging/rpm/openvibes-packages.gpg` by `scripts/sign-rpms.sh`, which
refuses the whole set if any package is unsigned or signed by another key.
The GitHub Release is created as a draft and published only after that
check, with the RPMs and `SHA256SUMS` (a release already made by hand for
the tag gets them uploaded instead); `openvibes-project.github.io`
rebuilds the dnf repository on its 30-minute schedule (no token). Spec:
`docs/specs/2026-09-27-releases-design.md`. `scripts/test-sign-rpms.sh`
tests the signing script with a throwaway key (CI's Fedora job).

## Known gaps

- Run as `sudo -u openvibes-admin`, audit entries name the service account
  and, as a hint, the person from `SUDO_USER`; sudo's own log is
  authoritative.
- Finding retention is set twice: `finding_retention_days` in `ingest.toml`
  and `maintenance --retention-days` (default 90 in both).

## How to test

```sh
scripts/build-rpm.sh
podman run --rm -v "$PWD:/src:Z" -w /src registry.fedoraproject.org/fedora:44 bash -c \
  'dnf -q -y install systemd selinux-policy-targeted && dnf -q -y install target/rpm/RPMS/x86_64/openvibes-*.rpm && bash scripts/check-rpm.sh'
```

`scripts/setup-lifecycle-e2e.sh OLD_DIR NEW_DIR` (CI job "Setup life
cycle") installs from lower-version RPMs (`OV_VERSION=0.0.9
OV_RPM_TOPDIR=… scripts/build-rpm.sh`) with the agent on the host, breaks
things and repairs, uninstalls keeping data and installs again (same CA,
same agent), updates to the current RPMs, and removes everything, checking
that no packages, files, accounts, database or roles remain.

`scripts/check-rpm.sh` (as root, after install) checks the users, modes and
owners, the `%config(noreplace)` flags, `systemd-analyze verify` on all
six units, the generated `llm-api-key`, the `openvibes-llm` sandbox lines
and its pre-start check's refusals, that its SELinux module compiles
against Fedora's policy, that the ingest, distribution, and vulns units stop with
SIGINT (an actual stop is not exercised here), and that the
binaries run and refuse a missing configuration.

CI: the `fedora` job (container `fedora:44`) runs `build-rpm.sh`, builds the
console RPM from its offline npm cache, and builds the agent RPM from the
pinned agent revision. The `systemd-e2e` job runs
`scripts/systemd-e2e.sh` on those RPMs under a real systemd; the integration
test then runs against the installed binaries
([integration-agent.md](integration-agent.md)).
