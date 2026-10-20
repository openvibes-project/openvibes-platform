-- OpenVIBES platform schema version 59: the rule-metadata index (roles
-- plan 2026-10-20 step 5a, ruling 8). One row per rule of each stored,
-- verified rule bundle: its title, message, the optional `explain` and
-- `check` text (at most 600 characters each, protocol rule fields read from
-- the verified payload) and its ATT&CK pairs. The console fills it when a
-- bundle is stored and backfills stored bundles on start; an alarm whose
-- rule has no row falls back to resolving the bundle. `techniques` holds the
-- distinct technique ids of `attack`, for the alarm list's filter.
CREATE TABLE console_rule_meta (
    rule_set_id text NOT NULL,
    rule_set_version bigint NOT NULL,
    rule_id text NOT NULL,
    rule_version bigint NOT NULL,
    title text NOT NULL,
    message text NOT NULL,
    explain text CHECK (char_length(explain) <= 600),
    "check" text CHECK (char_length("check") <= 600),
    attack jsonb NOT NULL,
    techniques text[] NOT NULL,
    PRIMARY KEY (rule_set_id, rule_set_version, rule_id),
    FOREIGN KEY (rule_set_id, rule_set_version)
        REFERENCES rule_bundles (rule_set_id, version) ON DELETE CASCADE
);
GRANT SELECT, INSERT, UPDATE ON console_rule_meta TO "openvibes-console";
