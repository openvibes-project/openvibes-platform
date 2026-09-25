-- OpenVIBES platform schema version 15: local console identity, RBAC, asset
-- scopes, service accounts, triage, and structured audit metadata.

CREATE TABLE console_users (
    user_id uuid PRIMARY KEY,
    username text NOT NULL UNIQUE,
    display_name text NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    auth_generation bigint NOT NULL DEFAULT 0 CHECK (auth_generation >= 0),
    created_at timestamptz NOT NULL,
    disabled_at timestamptz,
    CHECK (length(username) BETWEEN 1 AND 64),
    CHECK (username = lower(username)),
    CHECK (username ~ '^[a-z0-9][a-z0-9._@+-]*$'),
    CHECK (length(display_name) BETWEEN 1 AND 160),
    CHECK ((enabled AND disabled_at IS NULL) OR (NOT enabled AND disabled_at IS NOT NULL))
);

CREATE TABLE console_credentials (
    user_id uuid PRIMARY KEY REFERENCES console_users ON DELETE CASCADE,
    password_phc text NOT NULL,
    changed_at timestamptz NOT NULL,
    must_change boolean NOT NULL DEFAULT false
);

CREATE TABLE console_auth_throttle (
    bucket_sha256 bytea PRIMARY KEY CHECK (length(bucket_sha256) = 32),
    window_started_at timestamptz NOT NULL,
    failures integer NOT NULL CHECK (failures >= 0),
    locked_until timestamptz,
    updated_at timestamptz NOT NULL
);

CREATE TABLE console_preauth (
    token_sha256 bytea PRIMARY KEY CHECK (length(token_sha256) = 32),
    csrf_sha256 bytea NOT NULL CHECK (length(csrf_sha256) = 32),
    browser_sha256 bytea NOT NULL CHECK (length(browser_sha256) = 32),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    CHECK (expires_at > created_at)
);
CREATE INDEX console_preauth_expiry_idx ON console_preauth (expires_at);

CREATE TABLE console_sessions (
    session_sha256 bytea PRIMARY KEY CHECK (length(session_sha256) = 32),
    csrf_sha256 bytea NOT NULL CHECK (length(csrf_sha256) = 32),
    user_id uuid NOT NULL REFERENCES console_users ON DELETE CASCADE,
    auth_generation bigint NOT NULL CHECK (auth_generation >= 0),
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    CHECK (idle_expires_at <= absolute_expires_at),
    CHECK (absolute_expires_at > created_at)
);
CREATE INDEX console_sessions_user_idx ON console_sessions (user_id, created_at DESC);
CREATE INDEX console_sessions_expiry_idx ON console_sessions (absolute_expires_at);

CREATE TABLE console_idempotency (
    actor_id text NOT NULL,
    operation text NOT NULL,
    key_sha256 bytea NOT NULL CHECK (length(key_sha256) = 32),
    request_sha256 bytea NOT NULL CHECK (length(request_sha256) = 32),
    response_status smallint NOT NULL CHECK (response_status BETWEEN 200 AND 599),
    response_body jsonb NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (actor_id, operation, key_sha256),
    CHECK (expires_at > created_at)
);
CREATE INDEX console_idempotency_expiry_idx ON console_idempotency (expires_at);

CREATE TABLE console_roles (
    role_id text PRIMARY KEY,
    display_name text NOT NULL,
    builtin boolean NOT NULL DEFAULT false,
    CHECK (role_id ~ '^[a-z][a-z0-9_]{0,63}$')
);
CREATE TABLE console_permissions (
    permission_id text PRIMARY KEY,
    scope_class text NOT NULL CHECK (scope_class IN ('agent', 'global'))
);
CREATE TABLE console_role_permissions (
    role_id text NOT NULL REFERENCES console_roles ON DELETE CASCADE,
    permission_id text NOT NULL REFERENCES console_permissions ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
);
CREATE TABLE console_role_bindings (
    binding_id uuid PRIMARY KEY,
    user_id uuid REFERENCES console_users ON DELETE CASCADE,
    service_account_id uuid,
    role_id text NOT NULL REFERENCES console_roles,
    asset_group_id uuid,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    revoked_at timestamptz,
    revoked_by text,
    CHECK (num_nonnulls(user_id, service_account_id) = 1),
    CHECK ((revoked_at IS NULL) = (revoked_by IS NULL))
);
CREATE UNIQUE INDEX console_role_bindings_active_unique_idx
    ON console_role_bindings (user_id, service_account_id, role_id, asset_group_id) NULLS NOT DISTINCT
    WHERE revoked_at IS NULL;
CREATE INDEX console_role_bindings_user_idx
    ON console_role_bindings (user_id) WHERE user_id IS NOT NULL;
CREATE INDEX console_role_bindings_service_account_idx
    ON console_role_bindings (service_account_id) WHERE service_account_id IS NOT NULL;

CREATE TABLE console_asset_groups (
    asset_group_id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    CHECK (length(name) BETWEEN 1 AND 128)
);
ALTER TABLE console_role_bindings
    ADD CONSTRAINT console_role_bindings_group_fk
    FOREIGN KEY (asset_group_id) REFERENCES console_asset_groups;
CREATE TABLE console_asset_group_selectors (
    asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE CASCADE,
    tag_key text NOT NULL,
    tag_value text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (asset_group_id, tag_key),
    CHECK (length(tag_key) BETWEEN 1 AND 64),
    CHECK (length(tag_value) BETWEEN 1 AND 256)
);
CREATE TABLE console_agent_tags (
    agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
    tag_key text NOT NULL,
    tag_value text NOT NULL,
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL,
    PRIMARY KEY (agent_id, tag_key),
    CHECK (length(tag_key) BETWEEN 1 AND 64),
    CHECK (length(tag_value) BETWEEN 1 AND 256)
);
CREATE INDEX console_agent_tags_membership_idx
    ON console_agent_tags (tag_key, tag_value, agent_id);

CREATE TABLE console_service_accounts (
    service_account_id uuid PRIMARY KEY,
    name text NOT NULL UNIQUE,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL,
    created_by text NOT NULL,
    disabled_at timestamptz,
    CHECK (length(name) BETWEEN 1 AND 128),
    CHECK ((enabled AND disabled_at IS NULL) OR (NOT enabled AND disabled_at IS NOT NULL))
);
ALTER TABLE console_role_bindings
    ADD CONSTRAINT console_role_bindings_service_account_fk
    FOREIGN KEY (service_account_id) REFERENCES console_service_accounts ON DELETE CASCADE;
CREATE TABLE console_service_tokens (
    token_id uuid PRIMARY KEY,
    service_account_id uuid NOT NULL REFERENCES console_service_accounts ON DELETE CASCADE,
    token_sha256 bytea NOT NULL UNIQUE CHECK (length(token_sha256) = 32),
    label text NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_by text NOT NULL,
    CHECK (length(label) BETWEEN 1 AND 128),
    CHECK (expires_at > created_at)
);
CREATE INDEX console_service_tokens_account_idx
    ON console_service_tokens (service_account_id, created_at DESC);

CREATE TABLE console_finding_triage (
    agent_id text NOT NULL,
    rule_set_id text NOT NULL,
    rule_id text NOT NULL,
    state text NOT NULL CHECK (state IN ('open', 'investigating', 'mitigated', 'accepted_risk', 'false_positive')),
    rule_version bigint NOT NULL CHECK (rule_version >= 0),
    assigned_to uuid REFERENCES console_users,
    note text,
    accepted_until timestamptz,
    version bigint NOT NULL CHECK (version > 0),
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL,
    PRIMARY KEY (agent_id, rule_set_id, rule_id),
    FOREIGN KEY (agent_id, rule_set_id, rule_id)
        REFERENCES current_findings (agent_id, rule_set_id, rule_id) ON DELETE CASCADE,
    CHECK ((state IN ('open', 'investigating')) OR (note IS NOT NULL AND length(note) BETWEEN 1 AND 4000)),
    CHECK ((state = 'accepted_risk' AND accepted_until IS NOT NULL)
        OR (state <> 'accepted_risk' AND accepted_until IS NULL))
);
CREATE TABLE console_finding_triage_history (
    event_id bigserial PRIMARY KEY,
    agent_id text NOT NULL,
    rule_set_id text NOT NULL,
    rule_id text NOT NULL,
    from_state text CHECK (from_state IS NULL OR from_state IN ('open', 'investigating', 'mitigated', 'accepted_risk', 'false_positive')),
    to_state text NOT NULL CHECK (to_state IN ('open', 'investigating', 'mitigated', 'accepted_risk', 'false_positive')),
    note text,
    changed_at timestamptz NOT NULL,
    changed_by text NOT NULL,
    FOREIGN KEY (agent_id, rule_set_id, rule_id)
        REFERENCES current_findings (agent_id, rule_set_id, rule_id) ON DELETE CASCADE,
    CHECK (note IS NULL OR length(note) BETWEEN 1 AND 4000)
);
CREATE INDEX console_finding_triage_history_key_idx
    ON console_finding_triage_history (agent_id, rule_set_id, rule_id, event_id DESC);

CREATE TABLE console_audit_retention (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    retention_days integer NOT NULL DEFAULT 365 CHECK (retention_days > 0),
    version bigint NOT NULL DEFAULT 1 CHECK (version > 0),
    updated_at timestamptz NOT NULL,
    updated_by text NOT NULL
);
INSERT INTO console_audit_retention (singleton, updated_at, updated_by)
VALUES (true, now(), 'migration');

ALTER TABLE audit_log
    ADD COLUMN request_id text,
    ADD COLUMN actor_kind text,
    ADD COLUMN actor_id text,
    ADD COLUMN actor_display text,
    ADD COLUMN authentication_method text,
    ADD COLUMN target_kind text,
    ADD COLUMN target_id text,
    ADD COLUMN reason_code text,
    ADD COLUMN source_address inet,
    ADD COLUMN user_agent text;
CREATE INDEX audit_log_console_time_idx ON audit_log (at DESC, id DESC);

DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes_console') THEN
        CREATE ROLE openvibes_console LOGIN;
    END IF;
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;

INSERT INTO console_roles (role_id, display_name, builtin) VALUES
    ('viewer', 'Viewer', true), ('analyst', 'Analyst', true),
    ('operator', 'Operator', true), ('admin', 'Admin', true);
INSERT INTO console_permissions (permission_id, scope_class) VALUES
    ('agents.read', 'agent'), ('agents.revoke', 'agent'),
    ('findings.read', 'agent'), ('findings.triage', 'agent'),
    ('tokens.read', 'global'), ('tokens.create', 'global'), ('tokens.revoke', 'global'),
    ('rules.read', 'global'), ('rules.upload', 'global'),
    ('audit.read', 'global'), ('audit.export', 'global'), ('audit.retention.manage', 'global'),
    ('rbac.read', 'global'), ('rbac.manage', 'global'), ('asset_groups.manage', 'global'),
    ('service_accounts.read', 'global'), ('service_accounts.manage', 'global');
INSERT INTO console_role_permissions (role_id, permission_id)
SELECT role_id, permission_id FROM (VALUES
    ('viewer', 'agents.read'), ('viewer', 'findings.read'), ('viewer', 'rules.read'),
    ('analyst', 'agents.read'), ('analyst', 'findings.read'), ('analyst', 'rules.read'),
    ('analyst', 'findings.triage'),
    ('operator', 'agents.read'), ('operator', 'agents.revoke'), ('operator', 'findings.read'),
    ('operator', 'rules.read'), ('operator', 'rules.upload'), ('operator', 'tokens.read'),
    ('operator', 'tokens.create'), ('operator', 'tokens.revoke'),
    ('admin', 'agents.read'), ('admin', 'agents.revoke'), ('admin', 'findings.read'),
    ('admin', 'findings.triage'), ('admin', 'tokens.read'), ('admin', 'tokens.create'),
    ('admin', 'tokens.revoke'), ('admin', 'rules.read'), ('admin', 'rules.upload'),
    ('admin', 'audit.read'), ('admin', 'audit.export'), ('admin', 'audit.retention.manage'),
    ('admin', 'rbac.read'), ('admin', 'rbac.manage'), ('admin', 'asset_groups.manage'),
    ('admin', 'service_accounts.read'), ('admin', 'service_accounts.manage')
) AS builtins(role_id, permission_id);

REVOKE ALL ON console_users, console_credentials, console_auth_throttle,
    console_preauth, console_sessions, console_idempotency, console_roles,
    console_permissions, console_role_permissions, console_role_bindings,
    console_asset_groups, console_asset_group_selectors, console_agent_tags,
    console_service_accounts, console_service_tokens, console_finding_triage,
    console_finding_triage_history, console_audit_retention FROM PUBLIC;
GRANT SELECT ON agents, certificates, current_findings, findings, rule_sets,
    rule_bundles, schema_version, console_roles, console_permissions,
    console_role_permissions, console_role_bindings, console_asset_groups,
    console_asset_group_selectors, console_agent_tags, console_service_accounts,
    console_service_tokens, console_finding_triage, console_finding_triage_history,
    console_audit_retention TO openvibes_console;
GRANT SELECT, INSERT, UPDATE ON console_users, console_credentials,
    console_auth_throttle, console_preauth, console_sessions, console_idempotency,
    console_role_bindings, console_asset_groups, console_asset_group_selectors,
    console_agent_tags, console_service_accounts, console_service_tokens,
    console_finding_triage, console_audit_retention TO openvibes_console;
GRANT SELECT, INSERT ON audit_log TO openvibes_console;
GRANT USAGE ON SEQUENCE audit_log_id_seq, console_finding_triage_history_event_id_seq
    TO openvibes_console;
GRANT INSERT ON console_finding_triage_history TO openvibes_console;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM openvibes_console;
