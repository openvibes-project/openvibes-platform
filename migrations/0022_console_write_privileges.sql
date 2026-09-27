-- OpenVIBES platform schema version 22: narrow console writes and lock rights.
GRANT DELETE ON console_idempotency, console_asset_group_selectors,
    console_agent_tags TO openvibes_console;
GRANT INSERT ON rule_bundles TO openvibes_console;

-- Row locks require UPDATE privilege on at least one column, but the console
-- must not be able to modify unrelated rule, trust, finding, or agent data.
GRANT UPDATE (status, revoked_at) ON agents TO openvibes_console;
GRANT UPDATE (received_at) ON current_findings TO openvibes_console;
GRANT UPDATE (created_at) ON rule_sets TO openvibes_console;
GRANT UPDATE (added_at) ON rule_trust_keys TO openvibes_console;

-- A compromised console can revoke an active agent, but cannot restore one or
-- change an imported/revoked agent's state.
CREATE FUNCTION restrict_console_agent_status_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF current_user = 'openvibes_console'
       AND NEW.status IS DISTINCT FROM OLD.status
       AND NOT (OLD.status = 'active' AND NEW.status = 'revoked') THEN
        RAISE EXCEPTION USING
            ERRCODE = 'check_violation',
            MESSAGE = 'console role may only revoke active agents';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER restrict_console_agent_status_change
BEFORE UPDATE OF status ON agents
FOR EACH ROW EXECUTE FUNCTION restrict_console_agent_status_change();
