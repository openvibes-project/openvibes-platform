-- OpenVIBES platform schema version 36: finds the recently closed cases whose
-- resolved items may have come back (docs/specs/2026-10-04-console-cases-design.md).
CREATE INDEX cases_closed_at_idx ON cases (closed_at DESC) WHERE status = 'closed';
