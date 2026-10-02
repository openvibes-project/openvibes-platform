# Own rules in the console — design draft

Board #19. Status: **draft for the user's decisions** (§8). No code until
they are made. User, 2026-09-28: users write their own rules in the web
console, findings rules and threat-alarm rules, signed like the baseline.

## 1. Goal

An operator writes a rule in the console, checks it against real hosts,
and publishes it. Every enrolled agent evaluates it from its next scan (or,
for an alarm rule, its next rule fetch), without anyone opening a terminal.

The design must keep two properties:

- **Agents trust signatures, not the platform.** An agent accepts a rule
  set only with a signature from a key in its own `agent.toml`, and the
  distribution service can neither add nor re-scope rule sets
  (distribution design §1). Own rules must not weaken that for the
  baseline.
- **Interface first.** Writing a rule is a form with live validation and a
  test, not a JSON file.

## 2. What exists today

- **Rule sets** are JSON documents with schema 1, signed as a
  `SignedRuleEnvelope` (Ed25519) by `openvibes-admin rules sign` on the
  signer's machine. The baseline key is offline, and the platform never
  holds a rule-signing key (baseline rules design §4).
- **Two kinds of rule, the same CEL subset v2:**
  - *snapshot* rules over `facts[...]` (processes, packages, ports), which
    raise findings;
  - *process_event* rules over `event[...]` (P14), which raise alarms.

  Event rules ship in their own rule sets (`baseline-alarms`), because an
  agent before P14 fails every `event[...]` rule.
- **Distribution:** `rule_sets`, `rule_trust_keys` and `rule_bundles` in
  the store, served by `openvibes-distribution`.
  - `openvibes-admin rules trust add | publish` manage them.
  - The console already previews and publishes an **already-signed**
    bundle (`POST /api/v1/rule-bundles/preview` and publish), with the
    permission `rules.upload`.
- **Agents** list their rule sets and trusted keys in `agent.toml`
  (`[[rule_sets]]`). `install.sh` and `openvibes-admin agent command` write
  the baseline lines.
- **What the platform knows about a host:**
  - its packages (`package.names`, `package.count`, from the inventory);
  - its listening ports (P15 `host_listeners`, from which `port.*` can be
    rebuilt);
  - the alarms it raised, with masked process events.

  It does **not** store a host's raw facts (for example `process.names`).

## 3. What users write

The same rules the baseline uses: nothing new in the protocol or the agent.

| Field | Editor control |
|---|---|
| `id`, `version` | id typed once; version bumped on every publish |
| `title`, `finding_message` | text |
| `severity`, `confidence` | select, number 0–100 |
| `kind` | snapshot (finding) or process_event (alarm) |
| `programs` | alarm rules only: the program-name prefilter |
| `expression` | CEL v2, with completion of fact or `event` keys |

Limits are the protocol's (512 rules per set, CEL size, depth and node
limits), checked as you type.

## 4. Signing (the main open point) — decision D1

A console rule set still needs a signature that agents trust. Options:

- **A. A site signing key held by the platform.**
  - Setup generates an Ed25519 key for the site rule sets
    (`/var/lib/openvibes-console/site-rules.key`, 0600, owned by the
    console's service user). Its public key becomes a trust line
    (`site site-1 KEY`) in `rule_trust_keys` and in every agent command.
  - Publishing in the console signs and stores the bundle in one step.
  - Because the key is online, the console can also re-sign before expiry,
    and Health warns if it can't.
  - **Risk:** whoever controls the console process can publish any rules
    *in the site sets* to every agent that trusts them. The baseline sets
    stay untouched: their key is still offline, and agents trust keys per
    rule set.
  - A rule can raise false findings or alarms, or cost CPU within the
    evaluation limits. It cannot run code, read files or change the host.
  - **It can leak facts one bit at a time.** A finding's `evidence` names
    fact keys, never their values, and alarm events are masked before
    they are sent. But whether a rule matches is itself a bit, so a
    stolen key could publish rules that probe a value ("does a process
    name start with `a`?").
    - The cap: 512 rules per set, 1,024 across the two site sets, so at
      most about 1,000 bits per host per scan (hourly). Re-publishing
      can probe further, a version at a time.
    - What it can reach: only facts the agent collects. That is process
      names, packages and ports, plus the `event` keys for alarm rules.
      The platform already receives the packages, the ports and the
      masked alarm events, so what's new to an attacker is mainly
      process names and unmasked command lines.
    - Each publish is audited, with the count of rules added (§7). A
      burst of near-identical rules is visible there and in the rule
      set's history.
    - Someone who controls the console process can already read
      everything the platform stores. The channel adds only what agents
      never send.
  - **Mitigations:**
    - separate permissions (D3);
    - publishing asks for the password again;
    - a full audit trail (§7);
    - rotation through a second trust line (agents accept several issuer
      keys per set).
- **B. Export, then sign offline.**
  - The console drafts and tests. "Export" downloads the rules JSON.
  - The admin runs `openvibes-admin rules sign` on the machine that holds
    the key, then uploads the envelope with the existing upload screen.
  - No new trust on the platform at all, but every change takes a
    terminal, a key file and two file transfers. In practice rules change
    rarely and slowly.
- **C. Both, by rule set.**
  - A as the default for the site sets, so it's quick.
  - An admin can mark a set **offline-signed**. The console then hides
    Publish for it and offers Export (B).
  - This suits a site that wants alarm rules signed offline but findings
    rules quick.
  - It costs a little more UI than A alone.

**Recommendation: A**, with B kept working (it already does: export plus
the existing upload). A is what makes "write a rule in the console" true,
and the risk is confined to the site sets, whose worst case is noise. C
only if the user wants offline signing for some sets from day one.

## 5. The editor

- **Where:** Rule sets → *Site rules* and *Site alarm rules* → a list of
  rules with their state (draft, published vN) → a rule panel with the
  form (§3).
- **Validation, live:** the server compiles the draft with the agent's own
  `openvibes-rules` loader. The editor shows errors at their position:
  syntax, an unknown `event` key, a type error, a limit. For a fact key it
  warns when the key is unknown. Facts are open-ended, so that's a
  warning, never an error.
- **Test against a host:** pick a host and see matches, no match, or
  unavailable with the reason.
  - Snapshot rules: the facts the platform can rebuild for that host.
  - Alarm rules: the host's recent alarm events, or a typed sample event.
  - Rules over facts the platform doesn't hold (for example
    `process.names`) show **unavailable here**, and the panel says the
    agent will evaluate them.
- **Dry run before publish:** the whole draft set over every visible host.
  It shows the count of hosts each rule would match, unavailable counts,
  and the slowest rule by evaluation cost. Publish shows this summary
  again with the diff to the published version.
- **Test data — decision D4:**
  - **A.** Rebuilt facts only: packages and ports. Honest, and works today.
  - **B.** Agents also upload their full fact set at each scan, a new
    protocol message plus storage, so every rule tests for real.
  - **C.** A as now and B later, behind its own card.

  Recommendation **C**.

## 6. Distribution and agents — decisions D2 and D5

- **D2, which rule sets:**
  - **A.** Two site sets, `site` (findings) and `site-alarms` (alarms),
    like the baseline pair, so a pre-P14 agent never gets alarm rules.
  - **B.** One set for both kinds. Simpler, but it breaks agents before
    0.2.
  - **C.** One pair per asset group. This would allow per-group rules, but
    each group needs its own lines in `agent.toml`, set by whoever
    installs the host.

  Recommendation **A**; per-group rules can come later as C.
- **D5, existing agents** need the new `[[rule_sets]]` lines. The
  distribution service can't add them, by design:
  - **A.** `agent command` and `install.sh` include the site lines from
    now on. For hosts already enrolled, the console shows the two lines to
    paste, and Hosts flags agents that don't report the site set.
  - **B.** Ship the site lines empty in the agent package's default
    `agent.toml`, with the key filled in at install.
  - **C.** Let the agent accept new rule sets signed by an already-trusted
    key. This is a protocol and trust-model change: no.

  Recommendation **A**.
- **Publishing** is one insert in `rule_bundles`, as today. Agents pick up
  the new version at their next fetch, and a bad publish is undone by
  publishing the previous rules as a higher version.

## 7. Permissions and audit — decision D3

- **D3:**
  - **A.** One new permission, `rules.write`, to edit drafts, test and
    publish site rules.
  - **B.** Two: `rules.write` (edit drafts, test, dry run) and the
    existing `rules.upload` (publish, which now also signs site sets).
    This lets one person write and another publish.

  Recommendation **B**: the roles that publish today keep doing so, and
  a reviewer step comes free.
- **Audit**, every row with actor, rule set and version:
  - draft created, saved or deleted;
  - test and dry run (who ran them over which hosts, without the results);
  - publish (version, envelope SHA-256, rules added, changed and removed);
  - key generated or rotated (key id only, never the key).

  The rule set's history in the console shows each version's diff.

## 8. Decisions for the user

| # | Question | Options | Recommended |
|---|---|---|---|
| D1 | How site rules are signed | A: site key on the platform · B: export, sign offline · C: both, per set | **A** (B keeps working) |
| D2 | Which rule sets | A: `site` + `site-alarms` · B: one set · C: one pair per asset group | **A** |
| D3 | Who may do what | A: `rules.write` does all · B: `rules.write` drafts, `rules.upload` publishes | **B** |
| D4 | What a test runs against | A: packages and ports the platform holds · B: agents upload all facts · C: A now, B later | **C** |
| D5 | How existing agents get the site sets | A: new lines in installs, paste for old hosts · B: package default config · C: trust-by-key (no) | **A** |

## 9. Delivery, once decided

1. Store and API: drafts, validate, test and dry run (`rules.write`).
2. Site key in Setup, plus publish that signs (D1 A). Agent command and
   `install.sh` site lines (D5). Docs.
3. Console UI: rule list, editor panel, test, dry run, publish with diff,
   history.
4. Demo routes and e2e; a full-stack e2e where a console-published rule
   reaches a real agent.

One PR each, each with its component docs.
