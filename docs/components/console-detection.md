# Console detection details

## Purpose

Provides the observation-scoped API and web view for understanding a finding
or alarm: the values captured at evaluation, the conditions that evaluated
true, and the exact historical rule definition.

## Interfaces

- Finding and alarm detail responses carry their optional stored `Detection`
  explanation. The finding panel and the alarm's page ("Why it
  triggered") label incomplete, masked, summarized, and truncated values
  and show the recorded evaluation time.
- `GET /api/v1/compliance/{id}/rule` and
  `GET /api/v1/alarms/{id}/rule` resolve the original rule from the signed
  bundle identified by the observation's set version and preimage hash.
- Historical resolution verifies the recorded signature, including for
  expired bundles, retired sets, and keys removed from the active trust list.
  Legacy observations without a hash are resolved only if retained bundles
  agree on the rule definition.
- The rule-metadata index (`src/rules/meta.rs`, table `console_rule_meta`)
  keeps each stored bundle's rules: title, message, ATT&CK pairs, and the
  optional `explain` and `check` text (protocol rule fields the agent
  ignores), read from the verified payload's JSON and cut to 600
  characters. Bundles are verified as the historical read does
  (`stored_loader`, `verify_stored`: every stored key, at the bundle's
  creation time). A bundle is indexed when it is stored: console upload,
  draft publishing, and `openvibes-admin rules publish`. On start the
  console indexes, once and in the background, stored bundles without rows
  (at most 10,000 per start) and logs how many it indexed and how many did
  not verify. YAML payloads get no `explain`/`check`. An alarm's page
  shows `explain` and `check` under What happened, or the rule's title and
  message until the rule has them
  ([console-alarms.md](console-alarms.md#data-behind-the-page)).
- Each rule lookup first authorizes access to the referenced finding or alarm
  with the same permission and asset scope as the parent observation.

## Configuration and failure behaviour

No new configuration. Missing or unverifiable historical bundle content is
returned as unavailable while the stored explanation remains readable. A
hidden or unknown observation returns 404. The handler does not grant global
rule-list access. A bundle that fails to index is logged and left out; its
alarms fall back to `GET /api/v1/alarms/{id}/rule`, and the next start's
backfill tries again.

## How to test

```sh
cargo test --locked -p openvibes-console --test alarms_http --test rule_meta
cargo test --locked -p platform-store --test rule_meta
npm --prefix crates/openvibes-console/web run test
npm --prefix crates/openvibes-console/web run test:e2e:demo
```
