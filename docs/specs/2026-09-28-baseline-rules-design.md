# Baseline rules package and `rules keygen|sign` — design

Status: design approved in the project chat by the user (2026-09-28);
this spec awaits the user's review. Decisions: workspace `decisions.md`
("Baseline rules", 2026-09-28). Parent: admin TUI spec
(`2026-09-27-admin-tui-design.md` §6.3 step 11, §6.4 Repair), which names
this as its own sub-project.

## 1. Goal

A fresh platform gets useful, quiet findings without anyone writing a rule:
the project ships a signed baseline rule set as the RPM
`openvibes-rules-baseline`; Setup (step 11) trusts its key and publishes it,
and the local agent and every enrolled agent evaluate it. Operators no
longer use the agent repository's `sign_bundle` example: `openvibes-admin
rules keygen|sign` replace it, for the project and for anyone signing their
own rule sets (the example remains the agent's own test tool: its systemd container test
in CI signs with it, and no operator-facing agent doc names it, so the
agent repository needs no change).

Success: on a host set up with the Rules component, `openvibes-admin rules
list` shows `baseline` published, an agent on a host with an exposed Redis
reports `port.redis.exposed`, and a rules-only change ships without a
platform or agent release.

## 2. Decisions (from the chat)

| Question | Choice |
|---|---|
| Where rules live | New public repository `openvibes-project/openvibes-rules`, own tags and cadence (rules will change most often) |
| Signing key | Offline Ed25519 key on the user's machine; CI never holds it; separate from the RPM/repository key |
| Bundle lifetime | 730 days; re-signed on every rules change; Health warns under 90 days left |
| Compatibility | A CI allowlist of facts the oldest supported agent collects; no envelope change |
| First rule set | 14 exposure rules and 2 package rules (§5) |

## 3. Pieces and order

Each is one PR, reviewed by `@claude`, merged by the user:

1. **platform:** `openvibes-admin rules keygen` and `rules sign` (§4),
   component page `docs/components/openvibes-admin.md` (rules section) and
   `packaging.md` (single-host test steps use them).
2. **rules:** the new repository (§5, §6): created by the user (admins
   only) with the same settings as the others; the first PR adds the
   baseline, the checker, CI and the RPM.
3. **Pages:** `publish.yml` and `ci.yml` also take RPMs from
   `openvibes-rules` (§7).
4. **platform:** Health check for the published bundle's expiry (§8),
   after the Health screen (board #7) merges.

The first signed release (`v1`) follows 2 and 3: the user generates the
project key and signs.

## 4. `openvibes-admin rules keygen|sign`

Pure local file operations: no database, no schema check, no audit entry,
no root. They run on the signer's machine, which is usually not the
platform host.

```text
openvibes-admin rules keygen KEY_FILE --rule-set baseline --issuer openvibes-1
openvibes-admin rules sign KEY_FILE RULES_JSON --rule-set baseline --version N
                          --issuer openvibes-1 [--days 730] -o ENVELOPE_JSON
```

- **keygen** takes 32 bytes from `ring::rand::SystemRandom` (ring is
  already an admin dependency), writes them to `KEY_FILE` created new (`create_new`, mode 0600; an
  existing file is an error, never overwritten), and prints the key line
  `RULE_SET ISSUER_KEY_ID PUBLIC_KEY` (base64url public key), the format of
  `baseline.key` and of `rules trust add`'s arguments.
- **sign** refuses a key file that is not a regular file of exactly 32
  bytes, or whose mode grants any group or other permission (message names
  `chmod 600`). It reads `RULES_JSON`, validates it as a schema-1 rule set
  within the default resource limits, wraps its exact bytes in a
  `SignedRuleEnvelope` (`created_at` now, `expires_at` now + `--days`,
  1–3650, default 730), signs `openvibes_rules::signing_preimage`, then
  loads the result with `RuleLoader` and the derived public key before
  writing `-o` (created new; an existing file is an error). It prints the
  version, the expiry date and the envelope's SHA-256.
- Both reuse the `openvibes-rules` crate platform already pins, so the
  signature format cannot drift from the agent's.
- The version is not checked against earlier releases here; the rules
  repository's CI does that (§6).

Tests (`crates/openvibes-admin/tests/rules.rs`): keygen creates 0600 and
refuses an existing file; sign round-trips through `RuleLoader`; sign
refuses a 0644 key, a 31-byte key, invalid rules, `--days 0` and an
existing output; the signed envelope is accepted by `rules publish`
(database test, alongside the existing publish tests).

## 5. The `openvibes-rules` repository

```text
baseline/rules.json        source rule set (schema 1)
baseline/baseline.json     the signed envelope (committed by the signer)
baseline/baseline.key      baseline openvibes-1 PUBLIC_KEY
tests/<rule-id>.json       facts and the expected outcome, ≥1 match and ≥1 no-match per rule
facts.allowlist            facts the oldest supported agent (v0.1.0) collects
checker/                   small Rust binary: the checks in §6
openvibes-rules-baseline.spec
.github/workflows/{ci,release}.yml
README.md, CONTRIBUTING.md (AI disclosure), LICENSE (MIT), AGENTS.md
```

RPM `openvibes-rules-baseline`: `noarch`, version = the rule-set version,
installs `baseline.json` and `baseline.key` to
`/usr/share/openvibes/rules/` (0644 root), no scriptlets. Setup step 11 and
Repair already consume exactly this.

First rule set (version 1). Every rule reads a port fact with
`'N' in facts['port.tcp.exposed']` (UDP for SNMP); "exposed" means bound to
a non-loopback address, not proven reachable, which each message says.

| Severity | Rule id | Condition |
|---|---|---|
| critical | `port.docker_api.exposed` | tcp 2375 |
| high | `port.telnet.exposed` | tcp 23 |
| high | `port.rsh.exposed` | tcp 512, 513 or 514 |
| high | `port.vnc.exposed` | tcp 5900 |
| high | `port.redis.exposed` | tcp 6379 |
| high | `port.mongodb.exposed` | tcp 27017 |
| high | `port.elasticsearch.exposed` | tcp 9200 |
| high | `port.memcached.exposed` | tcp 11211 |
| medium | `port.ftp.exposed` | tcp 21 |
| medium | `port.smb.exposed` | tcp 139 or 445 |
| medium | `port.snmp.exposed` | udp 161 |
| medium | `port.postgresql.exposed` | tcp 5432 |
| medium | `port.mysql.exposed` | tcp 3306 |
| low | `port.ssh.exposed` | tcp 22 |
| low | `package.telnet_server.installed` | `'telnet-server' in facts['package.names']` |
| low | `package.rsh_server.installed` | `'rsh-server' in facts['package.names']` |

16 rules: 14 port rules (rsh and SMB are one rule each) and 2 package
rules. Confidence 100 for package rules, 90 for port rules
(the port number, not the service, is observed). Each `finding_message`
names the port and the usual fix (bind to loopback or firewall it).

## 6. Rules CI and release

PR and push to `main` (`ci.yml`), all through `checker`, which depends on
`openvibes-core` and `openvibes-rules` from the agent repository at a
pinned revision:

1. `rules.json` is a valid schema-1 rule set; rule ids are unique.
2. `baseline.json` verifies against `baseline.key` with `RuleLoader`, and
   its payload bytes equal `rules.json` byte for byte (what is reviewed is
   what is signed).
3. The envelope's version is greater than the latest release tag's (on a
   PR that changes `baseline/`) and at least 365 days remain before expiry.
4. Every fact an expression references (`facts['…']` string literals) is in
   `facts.allowlist`; any other access form fails the check.
5. Every rule has test cases, and each case evaluates through
   `RuleEngine` to its expected outcome (`match`, `no_match`,
   `unavailable`).
6. `rpmbuild -bb` on Fedora 44 succeeds and `rpmlint` has no errors.

Release (`release.yml`, on a `v*` tag, admins only): run the checks, build
the RPM, sign it with the existing `RPM_SIGNING_KEY` secret (the repository
key, as platform and agent do), attach it to the GitHub release, and
dispatch the Pages publish with `PAGES_DISPATCH_TOKEN`.

The signer's routine: edit `rules.json` and tests, `openvibes-admin rules
sign …` with the next version, commit `baseline.json`, open a PR, merge,
tag `vN`.

## 7. Pages

`publish.yml` downloads release RPMs from `openvibes-rules` alongside
platform and agent; `ci.yml` takes the latest `main` artifact the same way.
The installer's end-to-end test then covers Setup step 11 with a real
package: `rules list` shows `baseline` published.

## 8. Health

The Health screen and `openvibes-admin` health checks report a problem
when the newest published bundle of a trusted rule set expires in under 90
days, naming the rule set and the date, with the action "install the newer
package and run Repair, or publish a newer bundle". Expired is an error.

## 9. Failure behaviour

- Package missing from the repository: step 11 is skipped (unchanged).
- Envelope expired or bad signature at publish: `rules publish` already
  refuses; Setup reports the step as failed with that message.
- A rule needing a fact an older agent lacks cannot ship (CI check 4); if
  one did, it evaluates to `Unavailable`, not a failure.
- Lost or compromised signing key: a new issuer id (`openvibes-2`) can be
  trusted on the platform next to the old one, but every agent's
  `trusted_keys` also needs it, which today means editing each agent's
  config. Key rotation is out of scope; it gets its own design when needed.

## 10. Out of scope

New facts or collectors; key rotation; Windows rules; rule contributions workflow beyond
CONTRIBUTING; automatic re-signing; per-rule enable/disable in the console.
