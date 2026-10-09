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

Database commands need the `openvibes-admin` account: only it reads
`admin.toml` (0640) and has the database's peer login. With the packaged
`/etc/openvibes/admin.toml` (#79, `src/run_as.rs`), an operator who cannot
read it is started again through `sudo -n -u openvibes-admin` when the
operators' sudoers rule allows that without a password, and root through
`runuser -u openvibes-admin`; otherwise the error names the file, "permission
denied", and the `sudo -u openvibes-admin` form. A `--config` given on the
command line is used as is.

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
Configuration, Database, Health), `Shift+Tab` back. In any field being edited,
`Ctrl+U` empties it (other Ctrl chords are ignored, never typed as letters).
Every screen starts with the OpenVIBES wordmark (one line, `OpenVIBES`, the
tabs and the version, on a terminal under 30 rows, #78; otherwise six rows,
figlet's standard font: "Open" in white, "VIBES" in the brand teal
`#36b9e0`), the tabs on its last row (the current one highlighted), and the
version on the right; with `NO_COLOR` set it is plain text.

**Setup**: opens first on a host without `/etc/openvibes/setup.toml`. A
form: components (ingest and console always; distribution, vulns, rules,
the agent on this host on by default; the assistant off), hostname, other
names or addresses, CA mode (quick or careful) and the root key file.
Ingest and console show `[•]` (always installed, not a box to untick). A dim
line under the form says what the row under the cursor means (install
walkthrough, 2026-10-08). The field rows are numbered after the last
component, so each row is its own cursor position.
`Start` asks for the user's password once (masked; the user needs sudo
rights, not operator membership), writes the plan through `helper
setup-plan`, then runs one step per screen refresh through `helper
setup-step`, showing each step's state on one line (cut with "…" at the
screen's width; the step a run stopped at has its whole detail under the
list; the console step reads "admin account ready (password at the end)",
never the password). Pressing Start draws this list before the first step
runs (a step blocks the screen while it runs, e.g. dnf); while one runs, the
footer says keys wait, and the package step says it can take a few minutes.
The first step that fails or waits
stops the run and drops the password; `r` asks for it again and continues
from that step, and every other action (`c`, `u`, `m`, `x`, below) still
works from there; `Esc` returns to them without retrying (#73). Three
wrong passwords close the prompt. The finished screen
of an install is a few labelled rows (install walkthrough, 2026-10-08):
`Console` (the address), `Sign in` (admin and the generated password, shown
only then), `Root key` (where the only copy was written, and to move it
offline), then "Next: sign in, change the password, then add hosts under
Enrollment" and, when it applies, that the operator can run openvibes-admin
without sudo after logging in again. A detail in a wording the screen does
not know is shown as it is. No agent install line: hosts are added from the
console; `agent command` prints one for scripts. Repair, update and remove
runs end on every step's outcome. On a set-up
host, the Setup tab offers `c` check every step (`helper setup-status`),
`r` repair (every step with `--repair`: never a new CA), `u` update (the
installed OpenVIBES packages with any newer version, a backup file, then
the update job), `m` change components (the form filled from `setup.toml`;
added components are installed, unticked ones removed keeping data, ports
included), `p` change ports (the same form, on the port rows, #69; it says when a
default port is held by another program ("443 is in use"; "443 is in use by
another program" when the plan still has 443 and our unit is not running),
and shows the CA
as kept, with no root key row; moving
the agent ports takes a second Enter on Start, since agents on other hosts
keep calling the old ones until their install line is re-run; the ports a
plan moves away from are recorded in `/etc/openvibes/setup-moved-from` by
`helper setup-plan` and closed in firewalld once Readiness is done, as the
CLI's Repair does; only ports the Firewall step itself opened are closed, as
recorded in `/etc/openvibes/setup-opened-ports` (one open before Setup ran is
never Setup's; installs from before the record close nothing), and one another
program listens on, per `ss`, stays open with who uses it) and
`x` uninstall (keep data, or remove everything with a backup and the
typed hostname; the last line shows `sudo dnf remove openvibes-admin`).
The root key file defaults to the first free name in the home directory
(`openvibes-root-ca.key`, then `-2`, `-3`…), since Remove everything keeps
the old key; and `m` after a first install that stopped before the CA step
offers the install again, not a Repair (#87).
Only rows on screen take the focus: with keep data, one `j` goes from the
choice to `[ Uninstall ]` (#74).
As root no password is asked (#82): the TUI started with `sudo openvibes-admin` runs
its helper directly, keeping `SUDO_USER` so Setup still names the person who
started it (operators group, root key owner); otherwise the password prompt
suggests starting it that way (#92). Each runs one step
per refresh like the install, asking for the password
once. The steps are those of
`setup --quick` (below).

**Services**: each unit (`ingest`, `distribution`, `vulns`, `console`,
`llm`, `maintenance` timer) with boot state (`enabled`, `disabled`, `not
installed`), state (`active`, `failed`, …), readiness (`ready`, `not ready`,
`-`), and since when; below, the selected unit's last 50 journal lines,
tracing JSON shown as `HH:MM:SS LEVEL message key=value…` (fields in key
order; other lines as they are). `llm` is `openvibes-llm.socket`: it is what
is enabled and active, it has no readiness probe (one through it would load
the model), and its journal lines include the model server's and its
proxy's. The model server itself is inactive whenever the assistant is
idle; that is normal, and Health does not flag it (see
[openvibes-llm.md](openvibes-llm.md)).
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
Fields Setup owns (ingest's and distribution's `listen`, the console's
`development_listen` with direct TLS, and `public_origin`) are shown `(set by Setup)` and do
not open (#78): Setup checks those ports, opens the firewall and keeps the
origin in step, so they change with `p` (Change ports) on the Setup tab.
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
bundle are left out). With distribution installed and no rule set
published at all, a problem: agents get no rules (board #111). The site's own sets `site` and `site-alarms` (board
#107) warn under 30 days instead, with "publish again in the console to
renew": the signer re-signs only with a live password. With the signer set
up, also its `status.json`: no version state is a problem ("run Repair");
refusals in the last day are listed by code, a problem when they include
`rate`, `throttled`, `unavailable` or `version_state` (a wrong password now
and then is not); and the site key's first characters, noting that agents
need its lines from `agent command` and that after a reinstall agents
trusting an old site key refuse the site rules. Loaded on opening and on
`R`.

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
| `migrate [--additive]` | applies pending migrations; refuses a newer schema. `--additive` (the `openvibes-migrate` unit after a package upgrade, #77) applies nothing when a pending migration changes stored data and says to run Update, which backs up first | `schema version N` |
| `status` | summary (requires the current schema) | `schema version`, `agents active/offline/revoked`, `imported hosts`, `tokens usable`, `partitions OLDEST..NEWEST` or `none`, `partition count N`, `database size N MiB` |
| `maintenance [--retention-days 90] [--history-days 400]` | creates any missing partition from the finding retention cutoff to today + 7 days, drops older finding partitions (never today's), and deletes at most 10,000 expired audit events using the configured audit policy, then records today's per-host counts in `host_daily_counts` and deletes history older than `--history-days`. `--retention-days` must be 1 to 36500 and `--history-days` 30 to 3650 (else exit 2, before any change) | `created N partitions, dropped M, deleted K expired audit events` then `recorded history for N hosts, deleted M old rows` |
| `user create --username NAME --display-name LABEL [--role viewer|analyst|operator|admin] [--password-stdin] [--must-change]` | creates a local console account with a global built-in role; role defaults to admin; `--must-change` makes the password one-time (the user sets their own at first console sign-in, as with the console's New user) | prompts twice for the password without terminal echo; with `--password-stdin`, reads one line from standard input instead (scripts and Setup), same password rules |
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
openvibes-admin migrate", or "this upgrade changes stored data … run Update"
when a pending migration needs a backup) or a newer one ("upgrade
openvibes-admin"). A migration that deletes or rewrites rows, or drops or
retypes columns or tables, starts with a `-- openvibes: needs-backup` line;
a unit test holds every migration to that (13, 14, 16, 20 and 24, from
before the marker, are listed in `platform-store`). Setup's `schema` step
reports such a change as failed in Check and Repair (Repair migrates only
with `--additive`); a first install migrates fully. Errors
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
| `agent list [--offline \| --revoked \| --imported \| --health STATUS]` | one line per agent: id, status, last seen, version, and `claims ID` for an imported host whose files named an agent id; active agents end with `health <status>` and, when degraded, the reasons in brackets (protocol P12). `--offline` = active with no heartbeat for 3 minutes; `--imported` = hosts from export files (status `imported`, id `import.<install_id>`); `--health healthy\|degraded\|offline\|unknown` = active agents with that health. |
| `agent show ID` | id, status, enrolled (first import for an imported host), revoked, last seen, version, certificate count, and `claims ID` when set; for an active agent, its health and reasons, then the latest report: queue (pending, oldest age, dropped, rejected by reason), last scan and rule counts, each collector's outcome, each rule set's version, expiry and refusal, storage errors, threat alarms (`alarms on (eBPF)`, or `alarms off: why; fix: what to do`, then `alarms fix command: …` when there is one), clock jump, and when the report was written; `unknown agent` (exit 1) if absent |
| `agent revoke ID` | `revoked ID`; `agent already revoked`, `unknown agent`, or `imported hosts have no identity to revoke` are errors. The agent's next request gets `identity_revoked` (PM3). |
| `agent command [--platform HOST] [--root-cert PATH]` | the one-line command that installs and enrolls an agent on another host (`curl -fsSL https://openvibes-project.github.io/install.sh \| sudo sh -s -- --agent --platform HOST --token TOKEN --ca-sha256 FINGERPRINT`), with the platform's standing token (see `token fleet`): the same token every run, created on first use, so repeated runs add no rows; audited with the token's id. HOST defaults to Setup's hostname (`setup.toml`) and must be a DNS name or IP address; the fingerprint is the root certificate's (default `/etc/openvibes/pki/root.crt`). With the baseline rules package installed and its set served with a bundle signed by that same key (current, non-retired, issuer and trusted key equal to `baseline.key`), the line ends with `--rules SET,ISSUER,KEY` from `/usr/share/openvibes/rules/baseline.key`, and the installer configures the agent to fetch and trust that rule set (the key rides the same fingerprint-checked line). With the rule signer set up and `--rules` on the line, it also prints the `[[rule_sets]]` lines for the site's own sets (`site`, `site-alarms`, from `/etc/openvibes/site-rules.trust`, which Setup saves from `openvibes-signer seed`), to paste into each agent's `agent.toml`: the installer doesn't take them yet. No `restricted` key, so the agent restricts both; after a signer reinstall the key is new and the lines must be replaced. |

`show` and `revoke` are audited with the agent id as target. Health is
computed by `platform_store::health` (thresholds in the platform-store
page); an agent before P12 shows `unknown`.

## Token commands

| Command | Does |
|---|---|
| `token fleet` | the **standing token** every agent can enroll with: it never expires and has no use limit. Created on first use (also by `agent command` and Setup), shown again on every later run (its secret is kept in `standing_token_secret`, readable only by the admin account; ingest and the console see the hash). Only one is live at a time. To rotate it, `token revoke ID`: agents already enrolled keep their certificates and keep working, only new enrollments need the new token (the next `token fleet` or `agent command` makes it). One agent is cut off with `agent revoke`. `token create` still makes short-lived, limited-use tokens. |
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
| `rules publish-site --user USER --set site\|site-alarms [--password-stdin] [--socket PATH] FILE` | the site's own rules (board #107): asks for USER's console password (or reads it from stdin's first line), has the rule signer sign FILE (the signer checks the password, `rules.upload` and its limits itself, and picks the version), then publishes the envelope like `rules publish`. Refusals are explained in plain words (wrong username or password, locked, not allowed, over a limit, hourly limit, no version state). Setup puts `openvibes-admin` in the socket's group and trusts the site key for both sets. |
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
ignored), so run them as a user that can read it and its key files:
`sudo -u openvibes-console openvibes-admin assistant check`. They need
neither `admin.toml` nor the database, so they are not audited;
`model install` is, with the installed file name as the target.

| Command | Result |
|---|---|
| `assistant check` | Probes the backend: URL and location (local, own network, external), whether the model is listed, time to first token and speed (streaming backends), native tool calls and JSON-schema output, the lookup mode that will be used, the profile, and the recommended models (with whether each has passed the gate here). Fails if the backend cannot answer a plain question, or (with its own message) if the speed prompt ended at the output limit with no text: "the model spent its whole budget before answering (thinking model? use --reasoning off)". |
| `assistant eval [--cases FILE]` | Asks the question set (built in: 55 cases, 8 of them injection tests) against the evaluation fleet, never platform data, and prints lookup accuracy, fact completeness, contradictions or leaks, injections resisted and not exercised (a data-borne injection whose hostile text no lookup result showed the model), errors, median and p95 latency, and each failed case with its reason (`wrong lookup`, `lookup error`, `empty result`, missing facts). A lookup counts only when it found something unless the case sets `empty`. Exits non-zero when the gate (spec §10) fails. |
| `assistant model install FILE --sha256 HEX [--alias NAME] [--name FILE.gguf]` | For `openvibes-llm`: copies the GGUF file into `/var/lib/openvibes-llm/models/` through a temporary file, hashing what it copies, and installs it read-only (0444) only if the digest matches; then sets `OPENVIBES_LLM_MODEL`, `OPENVIBES_LLM_MODEL_SHA256`, and the alias in `/var/lib/openvibes-llm/model.conf`. Refuses names that are not plain `.gguf` file names and a different file under an installed name. The platform never downloads models. Run as `openvibes-admin` (its group owns the model store), then `systemctl restart openvibes-llm.socket` (the next question loads the new model). |

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
`--components` must include `ingest`; `rules` needs `distribution`;
`signer` (own rules, board #107; not in the default set while the console
has no publish screen) needs `console` and `distribution`. With `signer`,
the Console step runs `openvibes-signer seed --min-version 1` as the
signer's user (the site key and version state, kept if present) and adds
`openvibes-console` to `openvibes-signer-clients`, and saves the two trust
lines `seed` prints to `/etc/openvibes/site-rules.trust` (0644, for `agent
command`); Services then starts `openvibes-signer`. Remove everything
deletes `/var/lib/openvibes-signer` (the site key), the `openvibes-signer`
account and the clients group, and says so: after a reinstall the key is
new, so agents need its lines again.
A `setup.toml` from before the port choices (0.1.1) has no port fields;
each missing one is taken from the service using it (`console.toml`
`development_listen` with direct TLS, `ingest.toml`/`distribution.toml`
`listen`), else its default, and the plan is saved with them on the next
helper run, so Repair never moves a working service back (#76).
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
in `--repo-dir` with `localpkg_gpgcheck=1` unless `--allow-unsigned-local`;
an installed package whose packaged configuration file is missing, per
`rpm -V`, is reinstalled, which restores it and keeps edited ones, #82),
`postgres`, `operators` (the sudo user joins `openvibes-operators`),
`database`, `schema`, `ca` (quick: root in `/run/openvibes-ca`, its key
written once to `--root-key-out`, never over an existing file, otherwise
deleted; careful: waits for the signed intermediate), `certificates`
(hostname, `--san`, `localhost`, `127.0.0.1`, then the host's global IPv4
and IPv6 addresses from `ip -o addr show scope global` (not rotating IPv6
privacy or deprecated ones), container and VM bridges
(docker, podman, lxd, incus, calico, flannel, vxlan…) left out, VPN
interfaces kept, so the console opens by IP; a changed address makes the step Todo
and Repair reissues), `console` (`public_origin`
`https://HOST` or `https://HOST:PORT`, `development_listen` on the chosen
port with direct TLS, and the `admin` account; a generated password is
shown once), `services` (after the port check),
`firewall` (skipped without firewalld), `rules` (skipped until
`openvibes-rules-baseline` exists; done while the published version is at
least the installed package's, so Repair publishes a newer package; when
the package also carries `alarms.json`/`alarms.key` (rules v2), the
threat-alarm set is trusted and published the same way),
`agent` (the agent on this host, waits
up to 60 s for it to report; when the alarm rules are published and the
installed agent ships `/etc/audit/rules.d/openvibes-agent.rules` or, from
agent #57, its template `/usr/share/openvibes-agent/openvibes-agent.rules`
(a P14 agent), its `agent.toml` adds `process_events` to `collectors` and
the alarm rule set; an older agent never gets either, since it would refuse
the collector name. When the host's agent reads kernel audit (the exec rule
is in `/etc/audit/rules.d`; an eBPF host has none there) and
`/etc/audit/audit.rules` has `-a task,never` (Fedora's default, which
switches syscall auditing off), the step's line says alarms can't fire and
how to fix it; Setup never edits audit rules itself. Health shows the same
as a problem when the TUI runs as root),
`ready` (and, on a first install, makes sure the standing token exists,
which the console's install package and command carry; it shows no agent
line, only "add hosts in the console under Enrollment"; a Repair points to
`agent command`; a unit not ready after 30 s fails with its last journal line, e.g.
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
  remembered platform units, readiness (a unit not ready after 30 s fails
  with its own last journal line, as in Setup), and only then the agent,
  if it was running (board #111: started together with distribution, it
  found nothing listening and had no rules for a scan interval; it's
  started even when a unit isn't ready, since it fetches again soon
  itself). Setup's Agent step likewise waits for distribution to be ready
  before it restarts the agent.
- `setup --uninstall --keep-data [--backup PATH]`: stop and disable, close
  ports, remove the packages; database, CA and configuration stay.
  `--everything --confirm HOSTNAME` also drops the database and every
  `openvibes-*` role and deletes `/etc/openvibes`, `/etc/openvibes-agent`,
  `/var/lib/openvibes-*` and the service accounts. PostgreSQL stays;
  `openvibes-admin` itself is removed last with `sudo dnf remove
  openvibes-admin`, so its packaged `admin.toml` is left for rpm (#82).
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

## Assistant setup

`helper assistant-setup [--force]` (root, through sudoers) points the console at the bundled `openvibes-llm` model server: it gives the API key to the console's account, writes `[assistant]` into `console.toml`, stops a running model server, enables `--now openvibes-llm.socket` (the first request starts the server), restarts the console, and confirms the socket holds the port before tuning (`assistant_setup.rs`; see [openvibes-llm.md](openvibes-llm.md)).

`helper assistant-tune [--cpu] [--no-install] [--json]` (root; sudoers allows it plain and with `--json`) tunes the bundled model server for this host (`tune_run.rs`, decisions in `tune.rs`). When the console uses the local server it first checks that `openvibes-llm.socket` is active and listens on `127.0.0.1:OPENVIBES_LLM_PORT` (`systemctl show`), so the key goes only to systemd's socket, never to another local user holding the port; otherwise it refuses ("openvibes-llm.socket is not active; run sudo openvibes-admin helper assistant-setup", exit 1, nothing changed), and it checks again before the health wait. It never starts or stops the socket. It picks CPU threads (physical cores minus two, 2 to 16, unless you set `OPENVIBES_LLM_THREADS` or `OPENVIBES_LLM_GPU_LAYERS` in `llm.conf`), writes `/var/lib/openvibes-llm/tuning.conf`, stops `openvibes-llm-proxy.service` and `openvibes-llm.service` (when the console uses another backend: that only, no health wait or measurement), waits for `/health` (through the socket, which starts the server on the new tuning), times one chat call with the console's `[assistant.backend]` settings (but sent to `127.0.0.1:<port>` whatever the URL's host spelling, with the server's own key, `/etc/openvibes/llm-api-key`, never the configured `api_key_file`; a `[::1]` URL counts as another backend), and raises `[assistant.backend] deadline_seconds` (never lowers it) when a call takes over half of it. It writes `tune.json` (mode, threads, model, seconds per call, deadline, keys left alone, time) and prints one summary line (plus `left alone (set in llm.conf): <keys>` when it kept your values), or that JSON with `--json`. `--cpu` is the only mode so far and `--no-install` does nothing yet. Exit 0 on success; exit 1 when the server can't answer or the measurement fails, and then nothing changed (the previous tuning is restored). Once the tuning is in place, a deadline that could not be written, a console that did not restart, or an unsaved `tune.json` is a warning on stderr, still exit 0. It holds `/var/lib/openvibes-llm/tune.lock` while it runs; a second run fails at once ("another assistant-tune is running"). `assistant-setup` runs it; the TUI Health tab shows its summary. Test: `tests/assistant_tune.rs` (a debug-only hidden `--root DIR` stands in for `/`).

## Automatic steps after an upgrade

The user never types a command to finish an upgrade. Two helper verbs are
run by units that the packages start (neither unit has an `[Install]`).

`helper assistant-tune --auto` (root) is `assistant-tune` that decides for
itself (`tune::auto_skip`, no IO). It prints one line and exits 0 and does
nothing when `openvibes-llm.socket` is not enabled, `console.toml` has no
enabled `[assistant]` on the local backend, the model file named in
`/var/lib/openvibes-llm/model.conf` does not exist, or the host is already
tuned (`tuning.conf` exists). Otherwise it tunes as above; a failure (the
old tuning is restored) is the line, still exit 0. `openvibes-llm-tune.service`
(openvibes-llm package) runs it; a `%transfiletriggerin -P 900000` on
`/usr/libexec/openvibes-llm` starts it with `systemctl start --no-block`, after
the `%posttrans` scriptlets and systemd's restart of the model server. To tune again, run plain `assistant-tune`.

`helper rules-apply` (root) is Update's publish step without the TUI
(`setup/auto_rules.rs` calls `fleet::rules_check` then `fleet::rules_apply`,
the same trust-and-publish path). It prints one line and exits 0 (non-zero
only for misuse or a non-root caller): it skips when Setup is running
("Setup is running; it publishes the rules itself": it takes
`/run/openvibes-admin/setup.lock`), when Setup never ran (no `setup.toml`),
or when an Update or uninstall is half done; it publishes nothing when the
published version is already the package's or the set is retired; a key
Update would refuse is an error line, never trusted. It runs the sets Update
knows (`baseline`, and `alarms` when the package carries it). `openvibes-rules-apply.service`
(admin package) runs it, started by a transaction file trigger on
`/usr/share/openvibes/rules`, which fires after the whole transaction on
first install and on upgrade of the rules package (priority 900000, after
systemd's restart; the unit also wants `openvibes-migrate.service` first), so
it uses the new binary. A skipped or failed automatic publish is not retried
until the next rules or admin package transaction; Setup's Update publishes
it. Test: `setup/auto_rules.rs` unit tests.

`helper upgrade-migrate` (root; `setup/auto_migrate.rs`) is the only
`ExecStart` of `openvibes-migrate.service`. It takes Setup's lock (held:
"Setup or Update is running; if the services then refuse the schema, run
Update in Setup", exit 0), does nothing before Setup ran or while an update
or uninstall is half done, and runs `migrate --additive`: done means exit 0.
The store's "changes stored data" refusal (the compliance rename, migration
43, is one) makes it, like Update: stop the active ingest, distribution,
vulns, signer, console and maintenance units; back up the database
(`/var/backups/openvibes/upgrade-<time>.dump`, 0600, never overwritten, never
pruned, about twice the dump's size free during the copy); run Update's
migrate step (migrate, maintenance, publish a newer rules package); and
queue the stopped units to start (`start --no-block`) on every exit path. A
failed backup migrates nothing; a failed migration keeps the backup. Either
failure logs "upgrade migration failed", exits 1 (the unit shows as failed:
`journalctl -u openvibes-migrate`) and writes the half-done-update mark, so
later runs (the console's restarts, the maintenance timer) skip until Update
clears it (the mark is in `/run`: at most one retry per boot). The
decision is `auto_migrate::decide`; tests use the fake runner. Not built: a
Health line for a failed upgrade migration, and a free-space check before
the dump.

`assistant-tune` waits (up to 300 s, before it writes the new tuning) for systemd's jobs on `openvibes-llm.service` and its proxy before stopping the server, and tries a stop that systemd cancels ("Job for openvibes-llm.service canceled", the restart a package upgrade ends with) up to 3 times, 5 s apart. If `--auto` still fails, the old tuning is restored, `tune.lock` (only an `flock`, released at exit) blocks nothing, and the line says tuning is retried at the next upgrade or from Setup.
