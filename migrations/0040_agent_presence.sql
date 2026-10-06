-- OpenVIBES platform schema version 40: live agent presence. Ingest records
-- every heartbeat here, so "online" no longer lags the 5-minute throttled
-- write to agents.last_seen_at. The table is UNLOGGED: no WAL cost for a
-- write per heartbeat, and a database crash only empties it (readers fall
-- back to agents.last_seen_at until the next heartbeat). It holds one narrow
-- row per agent and no agents.last_seen_at index is touched.
CREATE UNLOGGED TABLE agent_presence (
    agent_id text PRIMARY KEY,
    seen_at timestamptz NOT NULL
);

-- The time an agent was last seen: the later of the saved heartbeat and the
-- live presence row. Every status read goes through this one function.
CREATE FUNCTION agent_seen_at(agent text, saved timestamptz) RETURNS timestamptz
    LANGUAGE sql STABLE PARALLEL SAFE
    AS $$ SELECT GREATEST(saved, (SELECT p.seen_at FROM agent_presence p WHERE p.agent_id = agent)) $$;

GRANT SELECT, INSERT, UPDATE ON agent_presence TO "openvibes-ingest";
GRANT SELECT ON agent_presence TO "openvibes-console";
