# Console detection details

## Purpose

Provides the observation-scoped API and web view for understanding a finding
or alarm: the values captured at evaluation, the conditions that evaluated
true, and the exact historical rule definition.

## Interfaces

- Finding and alarm detail responses carry their optional stored `Detection`
  explanation. The web panel labels incomplete, masked, summarized, and
  truncated values and shows the recorded evaluation time.
- `GET /api/v1/compliance/{id}/rule` and
  `GET /api/v1/alarms/{id}/rule` resolve the original rule from the signed
  bundle identified by the observation's set version and preimage hash.
- Historical resolution verifies the recorded signature, including for
  expired bundles, retired sets, and keys removed from the active trust list.
  Legacy observations without a hash are resolved only if retained bundles
  agree on the rule definition.
- Each rule lookup first authorizes access to the referenced finding or alarm
  with the same permission and asset scope as the parent observation.

## Configuration and failure behaviour

No new configuration. Missing or unverifiable historical bundle content is
returned as unavailable while the stored explanation remains readable. A
hidden or unknown observation returns 404. The handler does not grant global
rule-list access.

## How to test

```sh
cargo test --locked -p openvibes-console --test alarms_http
npm --prefix crates/openvibes-console/web run test
npm --prefix crates/openvibes-console/web run test:e2e:demo
```
