-- OpenVIBES platform schema version 1. See
-- docs/specs/2026-09-23-ingest-subproject-design.md, section 4.
CREATE TABLE agents (
    agent_id text PRIMARY KEY CHECK (agent_id ~ '^agent\.[0-9a-f-]{36}$'),
    status text NOT NULL CHECK (status IN ('active', 'revoked')),
    enrolled_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_seen_at timestamptz,
    scanner_version text,
    capabilities text[] NOT NULL DEFAULT '{}'
);
CREATE TABLE certificates (
    serial bytea PRIMARY KEY CHECK (length(serial) = 16),
    agent_id text NOT NULL REFERENCES agents,
    spki_sha256 bytea NOT NULL CHECK (length(spki_sha256) = 32),
    not_before timestamptz NOT NULL,
    not_after timestamptz NOT NULL,
    issued_at timestamptz NOT NULL,
    chain_pem text NOT NULL
);
CREATE TABLE enrollment_tokens (
    token_id uuid PRIMARY KEY,
    token_sha256 bytea NOT NULL UNIQUE CHECK (length(token_sha256) = 32),
    label text,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    expires_at timestamptz NOT NULL,
    max_uses integer NOT NULL DEFAULT 1 CHECK (max_uses > 0),
    revoked_at timestamptz
);
CREATE TABLE token_uses (
    token_id uuid NOT NULL REFERENCES enrollment_tokens,
    spki_sha256 bytea NOT NULL,
    agent_id text NOT NULL REFERENCES agents,
    serial bytea NOT NULL REFERENCES certificates,
    used_at timestamptz NOT NULL,
    PRIMARY KEY (token_id, spki_sha256)
);
CREATE TABLE findings (
    finding_id text NOT NULL,
    observed_day date NOT NULL,
    observed_at timestamptz NOT NULL,
    agent_id text NOT NULL,
    scan_id text NOT NULL,
    rule_id text NOT NULL,
    rule_version bigint NOT NULL,
    severity text NOT NULL,
    confidence smallint NOT NULL,
    message text NOT NULL,
    evidence text[] NOT NULL,
    received_at timestamptz NOT NULL,
    origin text NOT NULL CHECK (origin IN ('online', 'import')),
    authenticated boolean NOT NULL,
    PRIMARY KEY (finding_id, observed_day)
) PARTITION BY RANGE (observed_day);
CREATE TABLE current_findings (
    agent_id text NOT NULL REFERENCES agents,
    rule_id text NOT NULL,
    last_finding_id text NOT NULL,
    rule_version bigint NOT NULL,
    severity text NOT NULL,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    PRIMARY KEY (agent_id, rule_id)
);
CREATE TABLE audit_log (
    id bigserial PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    actor text NOT NULL,
    action text NOT NULL,
    target text,
    result text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'
);
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes_ingest') THEN
        CREATE ROLE openvibes_ingest LOGIN;
    END IF;
-- Roles are cluster-wide: parallel migrations (tests) can race on creation.
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
GRANT SELECT, INSERT, UPDATE ON agents, certificates, token_uses, findings, current_findings
    TO openvibes_ingest;
GRANT SELECT ON enrollment_tokens TO openvibes_ingest;
GRANT INSERT ON audit_log TO openvibes_ingest;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO openvibes_ingest;
