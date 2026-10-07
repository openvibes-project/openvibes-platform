-- OpenVIBES platform schema version 44: one row of problem counts per host
-- per day, written by maintenance, read by the console's history graphs
-- (spec 2026-10-07-overview-clarity-design §5). Additive.
CREATE TABLE host_daily_counts (
    day date NOT NULL,
    agent_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('active', 'stale', 'revoked', 'imported')),
    alarms_critical integer NOT NULL, alarms_high integer NOT NULL,
    alarms_medium integer NOT NULL, alarms_low integer NOT NULL,
    vulns_critical integer NOT NULL, vulns_high integer NOT NULL,
    vulns_medium integer NOT NULL, vulns_low integer NOT NULL,
    vulns_exploited integer NOT NULL, vulns_no_fix integer NOT NULL,
    needs_reboot boolean NOT NULL,
    compliance_critical integer NOT NULL, compliance_high integer NOT NULL,
    compliance_medium integer NOT NULL, compliance_low integer NOT NULL,
    PRIMARY KEY (day, agent_id)
);
GRANT SELECT ON host_daily_counts TO "openvibes-console";
