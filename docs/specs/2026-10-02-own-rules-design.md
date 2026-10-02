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

- **A. A site signing key held by the platform, hardened.**
  - **Where the key lives:** not in the console. The console is the most
    exposed process, since users put it on a network.
    - Setup generates an Ed25519 key for the site rule sets and gives it
      to a small **signer** (a new `openvibes-signer` unit, or the
      distribution service). The signer holds it as
      `/var/lib/openvibes-signer/site-rules.key`, 0600, under its own
      service user, and listens only on a local Unix socket.
    - **The signer checks the step-up itself** (lead, 2026-10-02).
      - Publishing asks for the user's password again. The console only
        passes it through, with the user name, over the socket.
      - The signer verifies it against the credential hash, using its own
        **read-only** database grant on the console's credential table.
      - It signs only if the password matches, the user holds
        `rules.upload` and is neither disabled nor on
        `password_must_change`, the rule set is a site set, and the rules
        pass the loader.
      - **Its password check is throttled like sign-in** (reviewer,
        2026-10-02), or a compromised console could use it to guess
        passwords outside the sign-in limiter:
        - a wrong password counts against the **same per-account failure
          bucket** as sign-in (5 per 15 minutes, as #129 does for
          set-password);
        - the signer's database role may write only that bucket;
        - refused attempts count toward its rate limit, not only
          successful publishes.
    - **It limits and records what it signs, out of the console's reach**
      (the implementation's baseline, reviewer and lead, 2026-10-02):
      - at most N publishes per hour per site (for example 6) and at most
        M rules changed per publish (for example 50), past which it
        refuses;
      - it re-checks the restricted-set rules itself (programs caps, no
        empty name), so a console that skipped them gains nothing;
      - its **own** audit line for every request, signed or refused (who,
        set, version, SHA-256, reason). It writes it to its own journal,
        outside the database, so a compromised console can't erase the
        trail.
    - **What this buys:** a console RCE can't read or copy the key, and it
      can't sign without a live user's password. It would have to capture
      one first (for example by waiting for a real step-up), within the
      rate limit, and leave a record it can't erase. That raises the bar
      without closing it fully. A second factor (TOTP or WebAuthn)
      verified by the signer would close it, and can come later.
    - The public key becomes a trust line (`site site-1 KEY`) in
      `rule_trust_keys` and in every agent command.
    - Because the key is online, the signer can also re-sign before
      expiry, and Health warns if it can't.
  - **Agents restrict what site sets can do**, in their own `agent.toml`.
    A stolen key signs bundles but can't edit that file. `install.sh`
    and `agent command` write `restricted = true` on both site sets
    (§6). For a restricted set the agent:
    - masks the `event` command line and arguments with the same
      `mask_args` it uses for alarms, before that set's rules see them,
      while the official baseline sets see the full form;
    - **refuses an alarm rule without a `programs` prefilter**, or with
      more than 8 names, or an empty name, or a set naming more than 32
      distinct programs.
      This is enforced in the agent's loader, because a stolen key never
      goes through the console. The console refuses the same at save.
    - **Absent means restricted** (reviewer and lead, 2026-10-02). A set
      whose line has no `restricted` key is restricted, except the
      project's offline-signed `baseline-alarms`. A forgotten or pasted
      line therefore fails closed, and the baseline alarm rules behave
      exactly as today. (`baseline` holds no alarm rules, so it's
      unaffected either way.) Only an explicit `restricted = false` lifts
      the restriction.
    - Exempting `baseline-alarms` by name is safe because each agent binds
      a rule set's name to the keys trusted for it, so the site key can't
      sign a bundle the agent accepts as `baseline-alarms`.
    - The agent tests cover an absent key, `true`, `false`, and the
      `baseline-alarms` exemption.
  - Restriction closes the bit-by-bit probe of command-line *values*.
    It does **not** cover the three points below, which each need their
    own measure: what a site alarm rule can still log, CPU per event, and
    where the key lives (above).
  - **The worst case, plainly.** Whoever can get the signer to sign can
    publish any rules in the site sets to every agent that trusts them.
    The baseline sets stay untouched: their key is still offline, and
    agents trust keys per rule set. No rule can run code, read files or
    change a host. The reach:
    - **A process-start logger for the named programs.** A site alarm
      rule whose expression is `true` raises an alarm for every start of
      the programs it names. Each alarm carries exe, cwd, uid, the
      ancestors' exes and cwds, and the masked arguments. With the caps
      above, that is every exec of up to 32 named programs, not every exec
      on the host. Honestly, 32 common names (`sh`, `bash`, `python3`,
      `curl` and so on) still cover a large share of a host's execs. The
      caps narrow the reach. The per-event CPU budget and the agent's
      collapse of repeats and 1,000-alarm queue bound the volume. The
      audit trail (§7) and the signer's own record show it.
    - **A one-bit channel over facts.** A finding's `evidence` names fact
      keys, never their values, but whether a rule matches is itself a
      bit, so rules can probe a value ("does a process name start with
      `a`?"). It's capped by 512 rules per set, 1,024 across the two
      site sets, so about 1,000 bits per host per hourly scan;
      re-publishing probes further, a version at a time. Restricted sets
      see masked command lines, so it can't reach secrets in argv: what's
      new to an attacker is mainly process names. Someone who controls
      the console can already read everything the platform stores.
    - **CPU on every host.** Alarm rules run on every process start, each
      within its own evaluation limit, so hundreds of rules tuned near
      that limit could pin a core on a busy host. The agent needs an
      **aggregate budget per event across all `process_event` rules**:
      past it, it stops evaluating that event and counts it in health.
      This is a prerequisite before site alarm rules ship (§9). Snapshot
      rules are already bounded per scan.
  - **Also visible and reversible:**
    - every publish is audited with the rules added, changed and removed
      (§7), so a burst of near-identical rules, or `true` expressions,
      stands out there and in the set's history;
    - permissions are separate (D3);
    - the key rotates through a second trust line, since agents accept
      several issuer keys per set.
  - **Cost:** masking runs on every exec that passes a restricted set's
    prefilter, not only when an alarm is raised. Both this and the
    aggregate budget are gated by an `alarms-cost` measurement (§9).
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

**Recommendation: A, hardened** (lead, 2026-10-02, from the reviewer's
read):
- the key is held by a local signer, not the console;
- site sets are restricted by the agent: masked command lines, a
  required and capped `programs` prefilter;
- an aggregate per-event CEL budget comes first.

B keeps working (export plus the existing upload). A is what makes
"write a rule in the console" true. Its worst case is stated above:
- an alarm logger for at most 32 named programs, which can still be a
  large share of execs;
- a slow one-bit channel without argv secrets;
- CPU bounded by the aggregate budget.

C only if the user wants some sets, for example the alarm rules,
offline-signed from day one.

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
    now on, each with `restricted = true` (§4). For hosts already enrolled, the console shows the two lines to
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
| D1 | How site rules are signed | A: site key on the platform · B: export, sign offline · C: both, per set | **A, hardened**: key in a local signer; restricted site sets (masked, capped prefilter); aggregate CEL budget first. B keeps working. |
| D2 | Which rule sets | A: `site` + `site-alarms` · B: one set · C: one pair per asset group | **A** |
| D3 | Who may do what | A: `rules.write` does all · B: `rules.write` drafts, `rules.upload` publishes | **B** |
| D4 | What a test runs against | A: packages and ports the platform holds · B: agents upload all facts · C: A now, B later | **C** |
| D5 | How existing agents get the site sets | A: new lines in installs, paste for old hosts · B: package default config · C: trust-by-key (no) | **A** |

## 9. Delivery, once decided

1. **Agent prerequisites**, before any site rule can ship:
   - an aggregate CEL budget per process event across all `process_event`
     rules, counted in health when it cuts;
   - `restricted` per rule set, **absent = restricted** except
     `baseline-alarms`: masked command lines, a required `programs`
     prefilter (at most 8 per rule, 32 distinct per set, no empty name),
     refused in the
     loader; tests for absent, `true`, `false` and the exemption;
   - **Gate:** an `alarms-cost` run with a restricted set at its limits
     stays within the P14 budget (#86).
2. Store and API: drafts, validation, test and dry run (`rules.write`).
   The console applies the same restricted-set checks at save.
3. The signer: a local service holding the site key.
   - It signs over a Unix socket only after verifying the user's password
     itself: a read-only grant on the credential hashes and user state,
     and write access only to the per-account sign-in failure bucket.
     Wrong passwords count there, and disabled or must-change users are
     refused.
   - It limits publishes per hour and rules per publish, re-checks the
     programs caps, and writes its own audit log in its journal, outside
     the database. A second factor comes later.
   - Setup generates the key. The trust line goes into `agent command` and
     `install.sh`, with the site lines (absent `restricted` = restricted,
     D5). Docs.
4. Console UI: rule list, editor panel, test, dry run, publish with diff,
   history.
5. Demo routes and e2e; a full-stack e2e where a console-published rule
   reaches a real agent, and a site alarm rule without `programs` is
   refused by that agent.

One PR each, each with its component docs.
