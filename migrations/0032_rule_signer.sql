-- OpenVIBES platform schema version 32: the rule signer's database role
-- (board #107, own rules). It verifies a console user's password itself
-- before signing site rules, so it reads only what a password check and
-- the `rules.upload` permission need, and writes only the sign-in failure
-- buckets. Its audit goes to its own journal, not audit_log.
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openvibes-signer') THEN
        CREATE ROLE "openvibes-signer" LOGIN;
    END IF;
-- Roles are cluster-wide: parallel migrations (tests) can race on creation.
EXCEPTION WHEN duplicate_object OR unique_violation THEN NULL;
END $$;
GRANT SELECT (user_id, username, enabled, password_must_change) ON console_users
    TO "openvibes-signer";
GRANT SELECT (user_id, password_phc, must_change) ON console_credentials TO "openvibes-signer";
GRANT SELECT (user_id, role_id, asset_group_id, revoked_at) ON console_role_bindings
    TO "openvibes-signer";
GRANT SELECT ON console_role_permissions TO "openvibes-signer";
GRANT SELECT, INSERT, UPDATE ON console_auth_throttle TO "openvibes-signer";
GRANT SELECT ON schema_version TO "openvibes-signer";
