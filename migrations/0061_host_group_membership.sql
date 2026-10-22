-- OpenVIBES platform schema version 61: stored host-group membership (roles
-- plan 2026-10-22 step 5b, task 2a). Every (group, host) pair of every kind,
-- by migration 53's rule: active hosts only; a manual group holds its picked
-- hosts; a rule or automatic group holds a host when it has conditions and
-- every one holds. Triggers keep it in the same transaction as the change,
-- so readers (`console_host_in_group`, scope, the lists) look pairs up
-- instead of evaluating conditions per request.
--
-- Concurrency: membership depends on a host's facts and a group's rule,
-- which two transactions can change at once, each seeing the other's old
-- value. Every refresh therefore takes one transaction-scoped advisory lock
-- (1870032226, 'ovmb') before reading, and holds it until commit: under READ
-- COMMITTED the refresh then sees every earlier change committed, and any
-- later change refreshes again. No foreign keys: their cascades would write
-- rows outside the lock; deletes are triggers too.
-- ponytail: one lock for all membership writes; relevant changes are rare
-- (facts, rules, revokes), per-group locks if they ever contend.
-- Additive: the deletes below are inside trigger functions and the backfill
-- only fills the new table, so no stored data changes (no needs-backup).
CREATE TABLE console_host_group_membership (
  asset_group_id uuid NOT NULL,
  agent_id text NOT NULL,
  PRIMARY KEY (asset_group_id, agent_id));
CREATE INDEX console_host_group_membership_agent_idx ON console_host_group_membership (agent_id);

-- One group's pairs, from its rule (conditions prepared once, as the Hosts
-- list did per request).
CREATE FUNCTION console_membership_refresh_group(gid uuid) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(1870032226);
  WITH conds AS MATERIALIZED (
    SELECT c.field, c.negate, c.vals, console_condition_likes(c.vals) AS likes,
           CASE WHEN c.field = 'ip' THEN c.vals::inet[] END AS nets
    FROM console_host_group_conditions c WHERE c.asset_group_id = gid),
  want AS (
    SELECT m.agent_id FROM console_host_group_members m
    JOIN console_asset_groups g ON g.asset_group_id = m.asset_group_id AND g.kind = 'manual'
    JOIN agents a ON a.agent_id = m.agent_id AND a.status = 'active'
    WHERE m.asset_group_id = gid
    UNION ALL
    SELECT a.agent_id FROM console_asset_groups g JOIN agents a ON a.status = 'active'
    WHERE g.asset_group_id = gid AND g.kind <> 'manual' AND EXISTS (SELECT 1 FROM conds)
      AND NOT EXISTS (SELECT 1 FROM conds c WHERE NOT COALESCE(
            console_condition_holds_prepared(a, c.field, c.negate, c.vals, c.likes, c.nets), false))),
  gone AS (DELETE FROM console_host_group_membership m
    WHERE m.asset_group_id = gid AND NOT EXISTS (SELECT 1 FROM want w WHERE w.agent_id = m.agent_id))
  INSERT INTO console_host_group_membership (asset_group_id, agent_id)
  SELECT gid, w.agent_id FROM want w ON CONFLICT DO NOTHING;
END $$;

-- One host's pairs, over every group.
CREATE FUNCTION console_membership_refresh_agent(aid text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(1870032226);
  WITH want AS (
    SELECT m.asset_group_id FROM console_host_group_members m
    JOIN console_asset_groups g ON g.asset_group_id = m.asset_group_id AND g.kind = 'manual'
    JOIN agents a ON a.agent_id = m.agent_id AND a.status = 'active'
    WHERE m.agent_id = aid
    UNION ALL
    SELECT g.asset_group_id FROM agents a JOIN console_asset_groups g ON g.kind <> 'manual'
    WHERE a.agent_id = aid AND a.status = 'active'
      AND EXISTS (SELECT 1 FROM console_host_group_conditions c WHERE c.asset_group_id = g.asset_group_id)
      AND NOT EXISTS (SELECT 1 FROM console_host_group_conditions c
                      WHERE c.asset_group_id = g.asset_group_id
                        AND NOT COALESCE(console_condition_holds(a, c.field, c.negate, c.vals), false))),
  gone AS (DELETE FROM console_host_group_membership m
    WHERE m.agent_id = aid AND NOT EXISTS (SELECT 1 FROM want w WHERE w.asset_group_id = m.asset_group_id))
  INSERT INTO console_host_group_membership (asset_group_id, agent_id)
  SELECT w.asset_group_id, aid FROM want w ON CONFLICT DO NOTHING;
END $$;

-- Hosts: a new active host (enrolment; imports are never active), and a
-- change to what conditions read or to whether the host is active. A
-- heartbeat repeating the same facts does not fire.
CREATE FUNCTION console_membership_agent_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM console_membership_refresh_agent(NEW.agent_id);
  RETURN NULL;
END $$;
CREATE TRIGGER console_membership_agent_inserted AFTER INSERT ON agents
  FOR EACH ROW WHEN (NEW.status = 'active') EXECUTE FUNCTION console_membership_agent_changed();
CREATE TRIGGER console_membership_agent_updated
  AFTER UPDATE OF status, os_id, os_version, hostname, last_address ON agents
  FOR EACH ROW WHEN ((OLD.status = 'active' OR NEW.status = 'active')
                     AND (OLD.status IS DISTINCT FROM NEW.status
                          OR OLD.os_family IS DISTINCT FROM NEW.os_family
                          OR OLD.distribution IS DISTINCT FROM NEW.distribution
                          OR OLD.hostname IS DISTINCT FROM NEW.hostname
                          OR OLD.last_address IS DISTINCT FROM NEW.last_address))
  EXECUTE FUNCTION console_membership_agent_changed();

-- Deleted hosts and groups leave (statement-level; `old_rows`).
CREATE FUNCTION console_membership_deleted() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM pg_advisory_xact_lock(1870032226);
  IF TG_TABLE_NAME = 'agents' THEN DELETE FROM console_host_group_membership m
    USING old_rows o WHERE m.agent_id = o.agent_id;
  ELSE DELETE FROM console_host_group_membership m
    USING old_rows o WHERE m.asset_group_id = o.asset_group_id;
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER console_membership_agents_deleted AFTER DELETE ON agents
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION console_membership_deleted();
CREATE TRIGGER console_membership_groups_deleted AFTER DELETE ON console_asset_groups
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION console_membership_deleted();

-- Conditions and picked hosts: each touched group once per statement. A new
-- group needs nothing: it has no conditions or picks until they are inserted.
CREATE FUNCTION console_membership_rule_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE gid uuid;
BEGIN
  IF TG_OP = 'INSERT' THEN
    FOR gid IN SELECT DISTINCT asset_group_id FROM new_rows LOOP
      PERFORM console_membership_refresh_group(gid);
    END LOOP;
  ELSIF TG_OP = 'DELETE' THEN
    FOR gid IN SELECT DISTINCT asset_group_id FROM old_rows LOOP
      PERFORM console_membership_refresh_group(gid);
    END LOOP;
  ELSE
    FOR gid IN SELECT asset_group_id FROM new_rows UNION SELECT asset_group_id FROM old_rows LOOP
      PERFORM console_membership_refresh_group(gid);
    END LOOP;
  END IF;
  RETURN NULL;
END $$;
CREATE TRIGGER console_membership_conditions_inserted AFTER INSERT ON console_host_group_conditions
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION console_membership_rule_changed();
CREATE TRIGGER console_membership_conditions_updated AFTER UPDATE ON console_host_group_conditions
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT
  EXECUTE FUNCTION console_membership_rule_changed();
CREATE TRIGGER console_membership_conditions_deleted AFTER DELETE ON console_host_group_conditions
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION console_membership_rule_changed();
CREATE TRIGGER console_membership_members_inserted AFTER INSERT ON console_host_group_members
  REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION console_membership_rule_changed();
CREATE TRIGGER console_membership_members_updated AFTER UPDATE ON console_host_group_members
  REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT
  EXECUTE FUNCTION console_membership_rule_changed();
CREATE TRIGGER console_membership_members_deleted AFTER DELETE ON console_host_group_members
  REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION console_membership_rule_changed();

-- A group's kind decides which half of the rule applies.
CREATE FUNCTION console_membership_kind_changed() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  PERFORM console_membership_refresh_group(NEW.asset_group_id);
  RETURN NULL;
END $$;
CREATE TRIGGER console_membership_kind_changed AFTER UPDATE OF kind ON console_asset_groups
  FOR EACH ROW WHEN (OLD.kind IS DISTINCT FROM NEW.kind)
  EXECUTE FUNCTION console_membership_kind_changed();

REVOKE ALL ON FUNCTION console_membership_refresh_group(uuid), console_membership_refresh_agent(text),
  console_membership_agent_changed(), console_membership_deleted(), console_membership_rule_changed(),
  console_membership_kind_changed() FROM PUBLIC;

SELECT console_membership_refresh_group(asset_group_id) FROM console_asset_groups;

-- Readers look the pair up; the rule itself now lives in the refreshes.
CREATE OR REPLACE FUNCTION console_host_in_group(agent text, gid uuid) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT EXISTS (SELECT 1 FROM console_host_group_membership m
                 WHERE m.asset_group_id = gid AND m.agent_id = agent) $$;

GRANT SELECT ON console_host_group_membership
  TO "openvibes-console", "openvibes-distribution", "openvibes-ingest";
