-- OpenVIBES platform schema version 6: rule distribution (SP2). Operators
-- publish offline-signed envelopes; the distribution service serves the
-- highest version of each live rule set, byte for byte.
CREATE TABLE rule_sets (
    rule_set_id text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    retired_at timestamptz
);
CREATE TABLE rule_trust_keys (
    rule_set_id text NOT NULL REFERENCES rule_sets,
    issuer_key_id text NOT NULL,
    public_key bytea NOT NULL CHECK (length(public_key) = 32),
    added_at timestamptz NOT NULL DEFAULT now(),
    removed_at timestamptz,
    PRIMARY KEY (rule_set_id, issuer_key_id)
);
CREATE TABLE rule_bundles (
    rule_set_id text NOT NULL REFERENCES rule_sets,
    version bigint NOT NULL CHECK (version > 0),
    envelope bytea NOT NULL CHECK (length(envelope) BETWEEN 1 AND 1048576),
    envelope_sha256 bytea NOT NULL CHECK (length(envelope_sha256) = 32),
    issuer_key_id text NOT NULL,
    created_at_ms bigint NOT NULL,
    expires_at_ms bigint NOT NULL,
    published_at timestamptz NOT NULL DEFAULT now(),
    published_by text NOT NULL,
    PRIMARY KEY (rule_set_id, version)
);
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes_distribution') THEN
        CREATE ROLE openvibes_distribution LOGIN;
    END IF;
-- Roles are cluster-wide: parallel migrations (tests) can race on creation.
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
-- Authentication reads agents and certificates; /ready reads schema_version.
GRANT SELECT ON agents, certificates, rule_sets, rule_bundles, schema_version
    TO openvibes_distribution;
