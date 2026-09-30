# openvibes-admin

Local operator CLI. Until the admin API exists it is **break-glass access**:
whoever can run it with the admin database role has full rights. Every
command, including failed ones, appends an `audit_log` entry with the
invoking OS user and `ok` or `error`, except a successful status read that
shows no host or finding data (`status`, `feeds status`, `rules list`,
`rules show`, `rules trust list`, `agent list`): the TUI's Health and
Database screens run those on every refresh. `agent show`, `vulns …`,
`token list` and `user …` stay audited. The actor is the real uid, which the
caller cannot choose, with `$USER` as a readable hint: `alice (uid 1000)`,
or `uid 1000` when `USER` is unset (timers, containers). Run through sudo
(`sudo -u openvibes-admin …`), the person is appended from `SUDO_USER`:
`openvibes-admin (uid 994) via sudo by alice`.

## Administration TUI

`openvibes-admin` with no subcommand opens the administration TUI: the
host-side work the web console deliberately does not do (admin TUI spec,
`docs/specs/2026-09-27-admin-tui-design.md`). It runs as the invoking user,
never listens on the network, needs no config file to open, and works over
SSH at 80×24 with the keyboard only; states are written as text. Without a
terminal (a pipe, cron) it exits 2 with a message; subcommands work as
before.

Who can use it: members of `openvibes-operators` (created by the RPM; add a
person with `usermod -aG openvibes-operators NAME`, then they log in again).
They start, stop and restart the OpenVIBES units through a polkit rule, and
read logs and read and save configuration files through the root helper,
without a password. `Tab` switches between the screens (Setup, Services,
Configuration, Database, Health). Every screen starts with the OpenVIBES wordmark (six rows,
figlet's standard font: "Open" in white, "VIBES" in the brand teal
`#36b9e0`), the tabs on its last row (the current one highlighted), and the
version on the right; with `NO_COLOR` set it is plain text.

**Setup**: opens first on a host without `/etc/openvibes/setup.toml`. A
form: components (ingest and console always; distribution, vulns, rules,
the agent on this host on by default; the assistant off), hostname, other
names or addresses, CA mode (quick or careful) and the root key file.
`Start` asks for the user's password once (masked; the user needs sudo
rights, not operator membership), writes the plan through `helper
setup-plan`, then runs one step per screen refresh through `helper
setup-step`, showing each step's state. The first step that fails or waits
stops the run and drops the password; `r` asks for it again and continues
from that step, and every other action (`c`, `u`, `m`, `x`, below) still
works from there; `Esc` returns to them without retrying (#73). Three
wrong passwords close the prompt. The finished screen
shows the root certificate's fingerprint, the console address and admin
password (shown only then), and an endpoint enrollment token. On a set-up
host, the Setup tab offers `c` check every step (`helper setup-status`),
`r` repair (every step with `--repair`: never a new CA), `u` update (the
installed OpenVIBES packages with any newer version, a backup file, then
the update job), `m` change components (the form filled from `setup.toml`;
added components are installed, unticked ones removed keeping data) and
`x` uninstall (keep data, or remove everything with a backup and the
typed hostname; the last line shows `sudo dnf remove openvibes-admin`).
Only rows on screen take the focus: with keep data, one `j` goes from the
choice to `[ Uninstall ]` (#74).
Each runs one step per refresh like the install, asking for the password
once. The steps are those of
`setup --quick` (below).

**Services**: each unit (`ingest`, `distribution`, `vulns`, `console`,
`llm`, `maintenance` timer) with boot state (`enabled`, `disabled`, `not
installed`), state (`active`, `failed`, …), readiness (`ready`, `not ready`,
`-`), and since when; below, the selected unit's last 50 journal lines.
Keys: `j`/`k` or arrows select, `s` start, `t` stop, `r` restart (each asks
`y/n`; the job is queued and the state follows on the next refresh), `R`
refresh, `q` or Ctrl-C quit. Unit states refresh every 5 s; the log is read
only on selection, `R` and after an action, since each read goes through
sudo and the auth log. Not an operator:
the TUI names the group to join. Every action is written to the journal
(`journalctl -t openvibes-admin`). `e` and `d` enable or disable the
selected unit at boot after asking for the user's password (`helper
unit-enable|unit-disable` through sudo; polkit cannot limit boot changes to
OpenVIBES units).

**Configuration**: one form per file, `/etc/openvibes/ingest.toml`,
`distribution.toml`, `vulns.toml`, `console.toml` (with the assistant's
`[assistant]` section) and `admin.toml` (`llm.conf` is an environment file
and is edited by hand). Only the fields listed for the service in
`src/fields.rs` can be set; clearing a value (Enter on an empty value)
removes the key, so the service default applies (shown as `(default)`).
Every change is checked at once by the service's own configuration type,
the same check the service runs at start, and the result is shown as
`valid` or `invalid: REASON`; the help line under the form gives each
field's range. Comments and layout in the file are kept. Keys: `h`/`l`
file, `j`/`k` field, `Enter` edit (`Enter` sets, `Esc` cancels), `u` puts
the file's value back, `w` save, `R` reload, `q` quit; leaving a file with
unsaved changes asks first. Save lists each change as `field: before →
after` and asks `y/n`; it refuses when the file was changed on disk since it
was opened, writes through `helper config-write` (checked again as root; the
file keeps its owner, group and mode, and the old one is kept as
`NAME.toml.bak`), then offers to restart the service. Each save is written
to the journal (`config-write SERVICE ok|failed`, never the content).

**Database**: the output of `status` (schema version, agents, partitions
oldest..newest, partition count, database size). A schema that is not
current, a newer one, or an unreachable database shows the CLI's error
instead. `m` migrate and `n` run maintenance now (as the daily timer does:
90-day retention) each ask `y/n`; the result is shown under the box. The
screen runs the CLI as `openvibes-admin` (`sudo -n -u openvibes-admin
openvibes-admin …`, the operators' sudoers entry), so each command keeps its
peer login, schema check and `audit_log` row; migrate and maintenance are
also journalled. `R` reloads.

**Health**: one line per check, problems first, each marked `problem` or
`ok`, with the problem count in the title: each installed unit (a problem
unless active and, where it has an endpoint, ready); the ingest and
distribution server certificates and the intermediate (a problem under 14
days to expiry, when Setup's repair renews them; also a problem when one
misses an address this host now has, e.g. after DHCP, which Repair fixes);
feed errors from `feeds
status` (an unreachable database is a problem here); disk use of
`/var/lib/pgsql` and each `/var/lib/openvibes-*` (a problem from 90 %);
each published rule set's current bundle from `rules list` (a problem under
90 days to expiry or expired, with the fix: install the newer rules package
and run Repair, or publish a newer bundle; retired sets and sets without a
bundle are left out). Loaded on opening and on `R`.

Every TUI action (service action, boot change, config save, Setup step) is
also recorded in `audit_log` when the database is reachable, through
`openvibes-admin audit note ACTION TARGET RESULT` (hidden; run as
`openvibes-admin`, so the actor names the operator via `SUDO_USER`). ACTION
and TARGET are 1 to 128 printable characters, RESULT is `ok`, `failed`,
`waiting` or `todo`; the note is the only row written. The journal line is
the record when the note cannot be written (no database yet during Setup).

`openvibes-admin helper` (hidden) is the root helper the TUI calls through
sudo; it checks its arguments first and refuses unless run as root:

- `logs UNIT LINES`: the unit must be one of the six, LINES 1 to 500;
- `config-read SERVICE`: prints `/etc/openvibes/SERVICE.toml` (`ingest`,
  `distribution`, `vulns`, `console`, `admin`; regular files only);
- `config-write SERVICE`: replaces that file with standard input (at most
  64 KiB of UTF-8) once the service's type accepts it: a temp file in
  `/etc/openvibes`, the original owner, group and mode, `SERVICE.toml.bak`,
  then an atomic rename. A refused or failed write leaves the old file.

## Configuration

`/etc/openvibes/admin.toml` (or `--config PATH`), bounded and strict like
every platform config:

```toml
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes-admin"
```

The admin role owns the schema and needs `CREATEROLE` (migration 1 creates
`openvibes-ingest`).

## Commands

| Command | Does | Prints |
|---|---|---|
| `migrate` | applies pending migrations; refuses a newer schema | `schema version N` |
| `status` | summary (requires the current schema) | `schema version`, `agents active/offline/revoked`, `imported hosts`, `tokens usable`, `partitions OLDEST..NEWEST` or `none`, `partition count N`, `database size N MiB` |
| `maintenance [--retention-days 90]` | creates any missing partition from the finding retention cutoff to today + 7 days, drops older finding partitions (never today's), and deletes at most 10,000 expired audit events using the configured audit policy. `--retention-days` must be 1 to 36500 (else exit 2, before any change) | `created N partitions, dropped M, deleted K expired audit events` |
| `user create --username NAME --display-name LABEL [--role viewer|analyst|operator|admin] [--password-stdin]` | creates a local console account with a global built-in role; role defaults to admin | prompts twice for the password without terminal echo; with `--password-stdin`, reads one line from standard input instead (scripts and Setup), same password rules |
| `user list` | lists usernames, status, active roles, display names, and last activity; never reads or prints password hashes | tab-separated rows |
| `user disable USERNAME` | disables the account and revokes its sessions atomically | `disabled local user NAME` |
| `user unlock USERNAME` | clears an active per-account login lock and audits the recovery; source-address throttles remain active | `unlocked local user NAME` |
| `user reset-password USERNAME` | replaces the password and revokes all sessions atomically; does not enable a disabled account | prompts twice without terminal echo |

Usernames are normalized to lowercase ASCII and limited to 64 characters.
Passwords use the same console NFC normalization, 15–128 Unicode-character
policy, Argon2id parameters, and local common-passphrase blocklist as browser
login. Passwords are never accepted as command-line arguments or written to
the audit log. The built-in common-passphrase list is a small seed list, not a
full compromised-password corpus.

Commands other than `migrate` refuse to run on an outdated schema ("run
openvibes-admin migrate") or a newer one ("upgrade openvibes-admin"). Errors
never print SQL or connection strings. If the audit entry cannot be
written, the command exits non-zero with a warning.

## User commands

The user commands are audited, including failed attempts. Creation provisions
the user, credential, initial role binding, and user-created audit event in one
store transaction. Disable and password reset invalidate all browser sessions.
Unlock clears only an active account bucket; IP/source throttles still protect
the service. The first account can be created after schema 23 is applied.

## Agent commands

| Command | Prints |
|---|---|
| `agent list [--offline \| --revoked \| --imported \| --health STATUS]` | one line per agent: id, status, last seen, version, and `claims ID` for an imported host whose files named an agent id; active agents end with `health <status>` and, when degraded, the reasons in brackets (protocol P12). `--offline` = active with no heartbeat for 15 minutes; `--imported` = hosts from export files (status `imported`, id `import.<install_id>`); `--health healthy\|degraded\|offline\|unknown` = active agents with that health. |
| `agent show ID` | id, status, enrolled (first import for an imported host), revoked, last seen, version, certificate count, and `claims ID` when set; for an active agent, its health and reasons, then the latest report: queue (pending, oldest age, dropped, rejected by reason), last scan and rule counts, each collector's outcome, each rule set's version, expiry and refusal, storage errors, clock jump, and when the report was written; `unknown agent` (exit 1) if absent |
| `agent revoke ID` | `revoked ID`; `agent already revoked`, `unknown agent`, or `imported hosts have no identity to revoke` are errors. The agent's next request gets `identity_revoked` (PM3). |
| `agent command [--platform HOST] [--root-cert PATH]` | the one-line command that installs and enrolls an agent on another host (`curl -fsSL https://openvibes-project.github.io/install.sh \| sudo sh -s -- --agent --platform HOST --token TOKEN --ca-sha256 FINGERPRINT`), with a new token (24 hours, 10 enrollments, label `agent command`, audited like `token create`). HOST defaults to Setup's hostname (`setup.toml`) and must be a DNS name or IP address; the fingerprint is the root certificate's (default `/etc/openvibes/pki/root.crt`). With the baseline rules package installed and its set served with a bundle signed by that same key (current, non-retired, issuer and trusted key equal to `baseline.key`), the line ends with `--rules SET,ISSUER,KEY` from `/usr/share/openvibes/rules/baseline.key`, and the installer configures the agent to fetch and trust that rule set (the key rides the same fingerprint-checked line). Setup's last screen shows the same line. |

`show` and `revoke` are audited with the agent id as target. Health is
computed by `platform_store::health` (thresholds in the platform-store
page); an agent before P12 shows `unknown`.

## Token commands

| Command | Does |
|---|---|
| `token create --expires Nh\|Nd [--uses N] [--label TEXT]` | 32 random bytes, base64url; printed **once** with its id. Only the SHA-256 is stored. `--expires` 1h to 365d, `--uses` 1 to 100000 (default 1); out-of-range values exit 2 before any change. |
| `token list` | id, state (usable, expired, used up, revoked), uses/max, expiry, label. Never shows tokens. |
| `token revoke ID` | revokes; an already-revoked or unknown id is an error. |

The audit target is the token id, never the token.

## Rules commands

Rule sets for the distribution service. Keys and bundles are signed
offline; the platform never holds a rule-signing key.

| Command | Does |
|---|---|
| `rules trust add RULE_SET ISSUER_KEY_ID PUBLIC_KEY_B64URL` | trusts a 32-byte Ed25519 key (base64url, no padding; weak keys refused) for the set, creating the set. A key (1 in 64) or an id starting with `-` is taken as a value, not a flag; no `--` is needed (also for `trust remove`). Prints `trusted` or `already trusted`. An id already used for a different or removed key is refused: ids are never re-used. |
| `rules trust list [RULE_SET]` | `SET ISSUER KEY added TIME [removed TIME]` per key |
| `rules trust remove RULE_SET ISSUER_KEY_ID` | stops trusting the key for future publishing; served bundles are unchanged (agents trust keys themselves) |
| `rules publish FILE` | verifies the envelope with the agent's own `openvibes-rules` loader against the set's currently trusted keys, then stores its exact bytes. Prints `published SET vN`, or `unchanged: …` for the same version with the same bytes. |
| `rules list` | `SET vN\|none keys K expires TIME\|- [signer-removed] [retired]`. `signer-removed`: the current bundle's key was removed; it is still served, but agents that dropped the key refuse it, so publish one signed by a trusted key. |
| `rules show RULE_SET` | per bundle, newest first: version, SHA-256, issuer, size, when and by whom published, expiry |
| `rules retire RULE_SET` | stops serving the set (404 to agents) and refuses further publishing; bundles are kept |
| `rules keygen KEY_FILE --rule-set SET --issuer ISSUER` | offline (no config or database): writes a new Ed25519 private key to `KEY_FILE` (32 bytes, 0600, never overwritten) and prints `SET ISSUER PUBLIC_KEY`, the arguments of `rules trust add` and the line of a package's `.key` file. `rules keygen --show-public KEY_FILE --rule-set SET --issuer ISSUER` prints that line again for an existing key (same permission checks as `sign`, nothing written), for when the first output was lost |
| `rules sign KEY_FILE RULES_JSON --rule-set SET --version N --issuer ISSUER [--days 730] -o OUT` | offline: signs the exact bytes of a schema-1 rule set into a new envelope (0644; valid from now for `--days`, 1–3650), checks that the agent's loader accepts it, and prints `signed SET vN, expires TIME, sha256 HEX`. Refuses a key file that group or others can access, a key that is not 32 bytes, an invalid rule set, and an existing `OUT`. |

Keep the key file off the platform host: `keygen` and `sign` are meant for
the signer's machine and write no audit row. The project's baseline rule
set is signed this way (the `openvibes-rules` repository).

`publish` refuses (exit 1, nothing stored):
- a file over 1,048,576 bytes (`envelope is larger than 1048576 bytes`), or
  one that is not an envelope (`not a signed rule envelope`);
- an unknown set, no trusted key, or a removed key (`untrusted issuer`);
- a bad signature or digest (`invalid signature`);
- an expired envelope, or one created in the future;
- a version not above the current one (`version N is not above current
  version C`), or the current version with different bytes (`version N
  already published with different content`);
- a retired set.

It warns on stderr when the bundle expires in less than 7 days. Publishers
of one set are serialized, so concurrent identical publishes store one row.

Audit targets: `SET vN sha256:HEX` for `publish` (none if the file is not
an envelope), `SET/ISSUER` for the trust commands, the set for `show`,
`retire`, and `trust list RULE_SET`.

## Vulnerability commands

| Command | Does |
|---|---|
| `feeds import FILE --source fedora-<rel>-<arch>` | imports a downloaded `updateinfo.xml` or `.xml.zst` (offline platforms), re-matches that release: `imported N advisories into SOURCE; M open on fedora REL` |
| `feeds import FILE --source rocky-N\|almalinux-N\|debian-N\|ubuntu-YY.MM` | imports an OSV `all.zip` (the ecosystem's, from `osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip`) for that release and re-matches it: `imported N advisories into debian-12; M open` (unreadable records are counted and skipped) |
| `feeds import FILE --source kev\|epss\|nvd\|euvd` | imports a CISA KEV JSON, an EPSS CSV (`.gz` or plain), an NVD API response page (only CVEs advisories name are kept), or an EUVD exploited list (the whole list: CVEs missing from it lose the mark): `imported N CVEs from kev` |
| `feeds status` | per source: advisories (or CVEs for `kev`, `epss`, `nvd`, `euvd`), last check, last change, last error |
| `vulns summary` | open count by severity and host count; open ones exploited in the wild (CISA KEV or EUVD), and open ones with no fix available yet, when any; hosts with a kernel fix installed but not booted (a separate state, not counted as open); the ten most affected hosts |
| `vulns list [--host H] [--severity S] [--cve ID] [--fixed]` | (vulnerabilities without a fix appear with `--host`, not fleet-wide, where they would repeat on every host) one line per vulnerability by priority (exploited first, then EPSS percentile, then severity, then CVSS, then oldest): severity, advisory, host, since, packages `installed -> fixed`, or `installed (no fix available)` (with `(running …)` for a kernel), CVEs, `exploited (KEV, due DATE, ransomware; EUVD)`, `EPSS 94.0% (top 1%)`, `CVSS 9.8`, and `(fix installed, reboot needed)` when only a reboot is missing |
| `vulns show ADVISORY\|HOST` | an advisory with its link, one line per CVE (`CVE-… CVSS 6.1 (3.1) CWE-79 KEV EUVD-… EPSS 94.0%: description`, first 200 characters), and hosts; or a host with its open vulnerabilities |

Hosts are named by hostname (else agent id); a host imported from export
files is marked `web-01 (imported)`, since its hostname is unsigned and may
repeat an enrolled host's. `--host H` and `vulns show H` take an agent id
or a hostname only one host has: a shared hostname is refused with the
matching ids (`web-01 matches 2 hosts: agent.…, import.… (imported); give
the id`) rather than merging their vulnerabilities.

All are audited; `feeds import` with the source as target.

## Import command (protocol P3b)

`import [--retention-days 90] PATH...` stores agent export files written by
`openvibes-agent export` on a host with no platform. `PATH` is a file or a
directory, whose `*.json` files are imported in name order (not
recursive; other files are skipped).

- Only regular files are read (a symlink to a device, a FIFO or a socket
  is refused), at most 8 MiB for an inventory and 1 MiB for a finding
  file, then decoded and validated with the same
  types and limits as online deliveries. A file time
  (`exported_at`, `collected_at`) more than an hour in the future is
  refused, since it would win newest-wins forever, and so is a `hostname`
  or `scanner_version` with control characters. Its kind
  comes from its members: `findings` (`FindingExport`) or `packages`
  (`InventoryExport`).
- The host is `import.<install_id>`, status `imported`: its own host, never
  an enrolled agent. A file's `agent_id` is kept only as
  `claimed_agent_id`; `hostname` is a label.
- Findings are refused one by one by the online rules (more than an hour in
  the future, older than `--retention-days`, no partition) and stored as
  `origin = 'import'`, unauthenticated; ones already stored are counted.
- An inventory replaces the host's packages when it is newer than the
  stored one, and the vulnerability service matches the host within a
  second. One without `os` (from an agent before P3b) is refused.
- One line per file, then totals:

```
/exports/openvibes-export-….json: imported 12 findings (3 already present, 1 refused: retention_expired)
/exports/openvibes-inventory-….json: inventory accepted (412 packages)
/exports/notes.json: refused: not an OpenVIBES export file
3 files: 12 findings, 1 inventories, 1 refused
```

Other lines: `inventory unchanged`, `older inventory ignored`, `refused:
larger than 8 MiB` (any file) or `larger than 1 MiB` (a finding file),
`not a regular file`, `not valid JSON`, `invalid: …`,
`no operating system: export again with a newer agent`, `database error:
…`. Control characters from files and file names are printed escaped
(`\u{1b}`), never raw. A refused file does
not stop the others; any refusal makes the exit code 1 (lines then go to
stderr). Re-running an import is always safe. One audit entry per run:
the totals and the paths given (`… from /exports`, at most 1,000
characters), so the log keeps where unsigned data came from.

## Assistant commands

`check` and `eval` read the `[assistant]` section of the console's configuration
(`--file`, default `/etc/openvibes/console.toml`; other sections are
ignored), so run them as a user that can read it and its key files. They
are audited with the configured model as the target; `model install` with
the installed file name.

| Command | Result |
|---|---|
| `assistant check` | Probes the backend: URL and location (local, own network, external), whether the model is listed, time to first token and speed (streaming backends), native tool calls and JSON-schema output, the lookup mode that will be used, the profile, and the recommended models (with whether each has passed the gate here). Fails if the backend cannot answer a plain question. |
| `assistant eval [--cases FILE]` | Asks the question set (built in: 53 cases, 6 of them injection tests) against the evaluation fleet, never platform data, and prints lookup accuracy, fact completeness, contradictions or leaks, injections resisted, errors, median and p95 latency, and each failed case. Exits non-zero when the gate (spec §10) fails. |
| `assistant model install FILE --sha256 HEX [--alias NAME] [--name FILE.gguf]` | For `openvibes-llm`: copies the GGUF file into `/var/lib/openvibes-llm/models/` through a temporary file, hashing what it copies, and installs it read-only (0444) only if the digest matches; then sets `OPENVIBES_LLM_MODEL`, `OPENVIBES_LLM_MODEL_SHA256`, and the alias in `/var/lib/openvibes-llm/model.conf`. Refuses names that are not plain `.gguf` file names and a different file under an installed name. The platform never downloads models. Run as `openvibes-admin` (its group owns the model store), then `systemctl restart openvibes-llm`. |

## Setup command (admin TUI spec §6)

`openvibes-admin setup --quick --components LIST --hostname NAME [--san
ADDR]... [--ca quick|careful] [--root-key-out PATH]
[--admin-password-file PATH] [--repo-dir DIR] [--allow-unsigned-local]
[--console-port PORT] [--ingest-port PORT] [--distribution-port PORT]`
runs as root, writes `/etc/openvibes/setup.toml` (0644) from the checked
arguments, then runs every Setup step in order and prints one line per step
(`TITLE: STATE DETAIL`). Exit 0 when every step is done or skipped, 3 when a
step waits (careful CA: sign the request offline, then run it again), 1 on a
failure, 2 on bad arguments (checked before the root check).
`--components` must include `ingest`; `rules` needs `distribution`.
Hostname and `--san` are lowercase DNS names or IP addresses; paths must be
absolute. Without `--quick` the command refuses and points to the TUI.

Ports (boards #45, #48, #61, `src/setup/ports.rs`): the console listens on
`--console-port` (default 443), ingest on `--ingest-port` (18423) and
distribution on `--distribution-port` (18424). The three must differ and
may not be 18430 or 18480-18483 (the assistant's and the health
listeners). Before anything changes, and again in `services` just before
the units start, Setup asks `ss -ltnpH` who listens on each chosen port.
Any listener counts, on any address, IPv4 or IPv6, except the unit that
owns the port (its `MainPID`, so a Repair or an Update finds our own
services). A taken port stops Setup with the holder (`nginx (pid N)` as
root, "another process" when `ss` cannot name it) and the first free
port to choose instead (from 8443 for the console, from 18425 for the
others); nothing is started, and the firewall step never opens a port
another process holds. `services` writes the ingest and distribution
ports into `ingest.toml`/`distribution.toml` `listen` (the console step
writes the console's), and restarts a running unit that is not on its
planned port yet. The address is `[::]` (IPv4 and IPv6 on one socket) when
`/proc/sys/net/ipv6/bindv6only` is 0, so a hostname that resolves to IPv6
only reaches the services (#72); `0.0.0.0` when IPv6 is off or that is 1.
A `listen` that differs from the plan's keeps `services` Todo even with
every unit running, and each unit whose file Setup rewrites is
try-restarted (the console by its own step), so Repair moves a running
host to `[::]` without a reboot. `ready` also connects to each service's planned port,
so a unit that answers its health check but not its port is not ready.
The local agent's `platform_url`/`distribution_url`, the firewall and the
agent command follow the plan: the command names a port only when it is
not the default (`--platform HOST:PORT`, `--rules … --distribution-port
N`), so a default platform prints the line every installer accepts.
The TUI's form has a "Console port" row and one "Agent ports (ingest,
distribution)" row: the defaults when free, otherwise the first free port
with "(443 is in use)" on the row; both editable.

Steps (`src/setup/`, each checks before it acts, so re-running is safe and
resumes): `packages` (dnf from the repository, or the one file per package
in `--repo-dir` with `localpkg_gpgcheck=1` unless `--allow-unsigned-local`),
`postgres`, `operators` (the sudo user joins `openvibes-operators`),
`database`, `schema`, `ca` (quick: root in `/run/openvibes-ca`, its key
written once to `--root-key-out`, never over an existing file, otherwise
deleted; careful: waits for the signed intermediate), `certificates`
(hostname, `--san`, `localhost`, `127.0.0.1`, then the host's global IPv4
addresses from `ip -o -4 addr show scope global`, container and VM bridges
(docker, podman, lxd, incus, calico, flannel, vxlan…) left out, VPN
interfaces kept, so the console opens by IP; a changed address makes the step Todo
and Repair reissues), `console` (`public_origin`
`https://HOST` or `https://HOST:PORT`, `development_listen` on the chosen
port with direct TLS, and the `admin` account; a generated password is
shown once), `services` (after the port check),
`firewall` (skipped without firewalld), `rules` (skipped until
`openvibes-rules-baseline` exists; done while the published version is at
least the installed package's, so Repair publishes a newer package),
`agent` (the agent on this host, waits
up to 60 s for it to report), `ready` (and, on a first install, an endpoint token, 24 hours, 10
uses; a Repair mints none and points to `agent command`; a unit not ready after 30 s fails with its last journal line, e.g.
`Address already in use`).

The same command maintains a set-up host (one action per call; each takes
the run lock `/run/openvibes-admin/setup.lock`, so a second Setup run is
refused while one works):

- `setup --repair [--console-port N] [--ingest-port N] [--distribution-port N]
  [--move-agent-ports]`: given ports go into `setup.toml` first (checked
  like a new plan's; a taken one changes nothing). Moving the ingest or
  distribution port is refused without `--move-agent-ports`: agents
  enrolled from other hosts keep calling the old port until the line from
  `agent command` is run on them again, which the output says. Ports moved
  away from are closed in firewalld. Then every step is checked, and only
  failed ones fixed. It
  never makes a new CA: with the CA files gone it stops and says how to
  recover. Certificates issued for other names are issued again; one
  expiring within 14 days is reported, not replaced.
- `setup --update [--backup PATH] [--update-repo-dir DIR]`: backup, stop
  the active OpenVIBES units (remembered in
  `/run/openvibes-admin/update-active`), `dnf upgrade` of exactly the
  installed `openvibes-*` packages (the agent too), `migrate` and
  `maintenance` (and, with the rules component, publishing the upgraded
  baseline rule set when it is newer than the published one), start the
  remembered units, readiness (a unit not ready after 30 s fails with its
  own last journal line, as in Setup).
- `setup --uninstall --keep-data [--backup PATH]`: stop and disable, close
  ports, remove the packages; database, CA and configuration stay.
  `--everything --confirm HOSTNAME` also drops the database and every
  `openvibes-*` role and deletes `/etc/openvibes`, `/etc/openvibes-agent`,
  `/var/lib/openvibes-*` and the service accounts. PostgreSQL stays;
  `openvibes-admin` itself is removed last with `sudo dnf remove
  openvibes-admin`.
- Backups: `pg_dump --format=custom` to PATH and `pg_dumpall --roles-only
  --no-role-passwords` to `PATH.roles.sql`, both new files (never over an
  existing one), 0600, owned by the sudo user, checked with `pg_restore
  --list` first.

Root helper verbs for the TUI, run with the user's own sudo rights and
password (no sudoers entry): `helper setup-plan PLANARGS` (writes
`setup.toml`; `SUDO_USER` becomes the operator), `helper setup-status`
(`STEP<TAB>STATE<TAB>DETAIL` per step), `helper setup-step STEP [--repair]`
(`STATE<TAB>DETAIL`, exit 0 whatever the state), `helper update-step STEP
[--backup PATH] [--repo-dir DIR]`, `helper remove-step STEP --components
LIST [--backup PATH] [--confirm HOSTNAME]`, `helper unit-enable UNIT`,
`helper unit-disable UNIT`. Arguments are checked before the root check.

## CA commands

The built-in CA (architecture spec, section 5). Keys are written `0600`,
certificates `0644`, always with create-new: **nothing is ever
overwritten**. A key and its certificate (or CSR) are written as a pair: if
either file already exists, neither is written, so no key is left without
its certificate.

| Command | Where | Writes | Audited |
|---|---|---|---|
| `ca init-root --out DIR` | offline machine | `root.crt`, `root.key` | no (no database there) |
| `ca intermediate-request --out DIR` | ingest host | `intermediate.key`, `intermediate.csr` | no |
| `ca sign-intermediate --root DIR --csr FILE --out FILE` | offline machine | intermediate certificate | no |
| `ca import-intermediate --cert F --key F --root-cert F` | ingest host | records root + intermediate in `ca_certificates` | yes, target = intermediate SHA-256 |
| `ca issue-server NAME [--san X]... --issuer-cert F --issuer-key F --out DIR` | ingest host | `NAME.crt` (leaf + intermediate), `NAME.key` | yes, target = NAME |

Operator flow: `init-root` offline, then `intermediate-request` on the ingest
host, carry only the **CSR** to the offline machine, `sign-intermediate`
there, carry only the **certificate** back, then `import-intermediate`.
The intermediate key never leaves the ingest host and the root key never
leaves the offline machine. `import-intermediate` refuses a key that does
not match the certificate, a certificate the given root did not sign, one
that is not an intermediate (the root itself, a leaf, or a CA without path
length 0), or one outside its validity, and records nothing then. Offline commands work without any config file.

## Test

```sh
eval "$(scripts/test-db.sh)"
cargo test --locked -p openvibes-admin
```

`tests/cli.rs` runs the built binary against a fresh database.
