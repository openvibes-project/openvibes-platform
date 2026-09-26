# openvibes-admin

Local operator CLI. Until the admin API exists it is **break-glass access**:
whoever can run it with the admin database role has full rights. Every
command, including failed ones, appends an `audit_log` entry with the
invoking OS user and `ok` or `error`. The actor is the real uid, which the
caller cannot choose, with `$USER` as a readable hint: `alice (uid 1000)`,
or `uid 1000` when `USER` is unset (timers, containers). Run through sudo
(`sudo -u openvibes_admin …`), the person is appended from `SUDO_USER`:
`openvibes_admin (uid 994) via sudo by alice`.

## Configuration

`/etc/openvibes/admin.toml` (or `--config PATH`), bounded and strict like
every platform config:

```toml
database_url = "postgresql:///openvibes?host=/run/postgresql&user=openvibes_admin"
```

The admin role owns the schema and needs `CREATEROLE` (migration 1 creates
`openvibes_ingest`).

## Commands

| Command | Does | Prints |
|---|---|---|
| `migrate` | applies pending migrations; refuses a newer schema | `schema version N` |
| `status` | summary (requires the current schema) | `schema version`, `agents active/offline/revoked`, `tokens usable`, `partitions OLDEST..NEWEST` or `none` |
| `maintenance [--retention-days 90]` | creates any missing partition from the retention cutoff to today + 7 days, so late or backlogged findings always have a partition; drops older ones, never today's. `--retention-days` must be 1 to 36500 (else exit 2, before any change) | `created N partitions, dropped M` |

Commands other than `migrate` refuse to run on an outdated schema ("run
openvibes-admin migrate") or a newer one ("upgrade openvibes-admin"). Errors
never print SQL or connection strings. If the audit entry cannot be
written, the command exits non-zero with a warning.

## Agent commands

| Command | Prints |
|---|---|
| `agent list [--offline \| --revoked]` | one line per agent: id, status, last seen, version. `--offline` = active with no heartbeat for 15 minutes. |
| `agent show ID` | id, status, enrolled, revoked, last seen, version, certificate count; `unknown agent` (exit 1) if absent |
| `agent revoke ID` | `revoked ID`; `agent already revoked` or `unknown agent` are errors. The agent's next request gets `identity_revoked` (PM3). |

`show` and `revoke` are audited with the agent id as target.

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
| `rules trust add RULE_SET ISSUER_KEY_ID PUBLIC_KEY_B64URL` | trusts a 32-byte Ed25519 key (base64url, no padding; weak keys refused) for the set, creating the set. Prints `trusted` or `already trusted`. An id already used for a different or removed key is refused: ids are never re-used. |
| `rules trust list [RULE_SET]` | `SET ISSUER KEY added TIME [removed TIME]` per key |
| `rules trust remove RULE_SET ISSUER_KEY_ID` | stops trusting the key for future publishing; served bundles are unchanged (agents trust keys themselves) |
| `rules publish FILE` | verifies the envelope with the agent's own `openvibes-rules` loader against the set's currently trusted keys, then stores its exact bytes. Prints `published SET vN`, or `unchanged: …` for the same version with the same bytes. |
| `rules list` | `SET vN\|none keys K expires TIME\|- [signer-removed] [retired]`. `signer-removed`: the current bundle's key was removed; it is still served, but agents that dropped the key refuse it, so publish one signed by a trusted key. |
| `rules show RULE_SET` | per bundle, newest first: version, SHA-256, issuer, size, when and by whom published, expiry |
| `rules retire RULE_SET` | stops serving the set (404 to agents) and refuses further publishing; bundles are kept |

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

All are audited; `feeds import` with the source as target.

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
| `assistant model install FILE --sha256 HEX [--alias NAME] [--name FILE.gguf]` | For `openvibes-llm`: copies the GGUF file into `/var/lib/openvibes-llm/models/` through a temporary file, hashing what it copies, and installs it read-only (0444) only if the digest matches; then sets `OPENVIBES_LLM_MODEL`, `OPENVIBES_LLM_MODEL_SHA256`, and the alias in `/var/lib/openvibes-llm/model.conf`. Refuses names that are not plain `.gguf` file names and a different file under an installed name. The platform never downloads models. Run as `openvibes_admin` (its group owns the model store), then `systemctl restart openvibes-llm`. |

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
