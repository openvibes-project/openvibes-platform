-- openvibes: needs-backup
-- OpenVIBES platform schema version 53: host groups of three kinds, labels
-- (spec 2026-10-16-roles-permissions-design.md §5, §12 part 4).
ALTER TABLE agents
  ADD COLUMN last_address inet,
  ADD COLUMN os_family text GENERATED ALWAYS AS
    (CASE WHEN os_id IS NULL THEN NULL WHEN os_id = 'windows' THEN 'windows' ELSE 'linux' END) STORED,
  ADD COLUMN distribution text GENERATED ALWAYS AS
    (CASE WHEN os_id IS NULL OR os_version IS NULL THEN NULL
          WHEN os_id IN ('rocky','almalinux') THEN lower(os_id || ' ' || split_part(os_version, '.', 1))
          ELSE lower(os_id || ' ' || os_version) END) STORED;
CREATE INDEX agents_os_family_idx ON agents (os_family);
CREATE INDEX agents_distribution_idx ON agents (distribution);

ALTER TABLE console_asset_groups
  ADD COLUMN kind text NOT NULL DEFAULT 'manual' CHECK (kind IN ('automatic','rule','manual')),
  ADD COLUMN description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
  ADD COLUMN auto_key text UNIQUE,                           -- 'os_family:linux', 'distribution:debian 12'
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN changed_at timestamptz,
  ADD COLUMN changed_by text,
  ADD COLUMN upgraded_from_tags boolean NOT NULL DEFAULT false,
  ADD CONSTRAINT console_asset_groups_auto_key_kind CHECK ((kind = 'automatic') = (auto_key IS NOT NULL));
ALTER TABLE console_asset_groups DROP CONSTRAINT console_asset_groups_name_key;

-- A free group name (case-insensitive, at most 128 characters) from `display`:
-- itself, else display || ' (suffix)', ' (suffix 2)', …; with suffix '' it is
-- ' (2)', ' (3)', …. The display part is cut so the suffix always fits. `keep`
-- is a group whose own name does not count. Insert one group per statement so
-- each call sees the names inserted before it (ingest's automatic groups too).
CREATE FUNCTION console_free_group_name(display text, suffix text, keep uuid DEFAULT NULL) RETURNS text
LANGUAGE plpgsql VOLATILE AS $$
DECLARE
  n integer := 0;
  tail text;
  candidate text := left(display, 128);
BEGIN
  WHILE EXISTS (SELECT 1 FROM console_asset_groups
                WHERE lower(name) = lower(candidate) AND asset_group_id IS DISTINCT FROM keep) LOOP
    n := n + 1;
    tail := ' (' || CASE WHEN suffix = '' THEN (n + 1)::text
                         WHEN n = 1 THEN suffix ELSE suffix || ' ' || n END || ')';
    candidate := left(display, 128 - char_length(tail)) || tail;
  END LOOP;
  RETURN candidate;
END $$;

-- names differing only in case were allowed before: later ones get " (2)"…
CREATE TEMP TABLE host_group_renamed (asset_group_id uuid PRIMARY KEY, old_name text NOT NULL);
DO $$
DECLARE g record;
BEGIN
  FOR g IN SELECT asset_group_id, name FROM (
             SELECT asset_group_id, name, row_number() OVER (
                      PARTITION BY lower(name) ORDER BY created_at, asset_group_id) AS rn
             FROM console_asset_groups) d
           WHERE rn > 1 ORDER BY lower(name), rn LOOP
    INSERT INTO host_group_renamed VALUES (g.asset_group_id, g.name);
    UPDATE console_asset_groups SET name = console_free_group_name(g.name, '', g.asset_group_id)
    WHERE asset_group_id = g.asset_group_id;
  END LOOP;
END $$;
CREATE UNIQUE INDEX console_asset_groups_name_unique ON console_asset_groups (lower(name));

CREATE TABLE console_host_group_conditions (
  asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE CASCADE,
  position smallint NOT NULL CHECK (position BETWEEN 0 AND 15),
  field text NOT NULL CHECK (field IN ('os_family','distribution','hostname','ip')),
  negate boolean NOT NULL DEFAULT false,
  vals text[] NOT NULL CHECK (cardinality(vals) BETWEEN 1 AND 64),
  CONSTRAINT console_host_group_conditions_no_null CHECK (array_position(vals, NULL) IS NULL),
  CONSTRAINT console_host_group_conditions_ip CHECK (field <> 'ip' OR vals::inet[] IS NOT NULL),
  PRIMARY KEY (asset_group_id, position));
CREATE TABLE console_host_group_members (
  asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE CASCADE,
  agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
  added_at timestamptz NOT NULL, added_by text NOT NULL,
  PRIMARY KEY (asset_group_id, agent_id));
CREATE INDEX console_host_group_members_agent_idx ON console_host_group_members (agent_id);
CREATE TABLE console_host_group_dismissed (auto_key text PRIMARY KEY, dismissed_at timestamptz NOT NULL, dismissed_by text NOT NULL);
CREATE TABLE console_host_labels (
  agent_id text NOT NULL REFERENCES agents ON DELETE CASCADE,
  label text NOT NULL CHECK (char_length(label) BETWEEN 1 AND 64),
  added_at timestamptz NOT NULL, added_by text NOT NULL,
  PRIMARY KEY (agent_id, label));
CREATE INDEX console_host_labels_label_idx ON console_host_labels (label);

-- '*' is the only wildcard; %, _ and \ are literal
CREATE FUNCTION console_glob_like(pattern text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT replace(replace(replace(replace(lower(pattern), '\', '\\'), '%', '\%'), '_', '\_'), '*', '%') $$;

CREATE FUNCTION console_condition_holds(a agents, field text, negate boolean, vals text[]) RETURNS boolean
LANGUAGE sql STABLE AS $$
  SELECT CASE
    WHEN field = 'os_family'    THEN a.os_family IS NOT NULL     AND negate <> (a.os_family = ANY (vals))
    WHEN field = 'distribution' THEN a.distribution IS NOT NULL  AND negate <> (a.distribution = ANY (vals))
    WHEN field = 'hostname'     THEN a.hostname IS NOT NULL      AND negate <> EXISTS (
        SELECT 1 FROM unnest(vals) v WHERE lower(a.hostname) LIKE console_glob_like(v) ESCAPE '\')
    WHEN field = 'ip'           THEN a.last_address IS NOT NULL  AND negate <> EXISTS (
        SELECT 1 FROM unnest(vals) v WHERE a.last_address <<= v::inet)
    ELSE false END $$;

-- ponytail: evaluated per (host, group) at query time; if large fleets need it,
-- materialise membership in a table refreshed on fact/rule changes.
CREATE FUNCTION console_host_in_group(agent text, gid uuid) RETURNS boolean LANGUAGE sql STABLE AS $$
  SELECT EXISTS (
    SELECT 1 FROM agents a JOIN console_asset_groups g ON g.asset_group_id = gid
    WHERE a.agent_id = agent AND a.status = 'active'
      AND CASE WHEN g.kind = 'manual' THEN EXISTS (
            SELECT 1 FROM console_host_group_members m WHERE m.asset_group_id = gid AND m.agent_id = a.agent_id)
          ELSE EXISTS (SELECT 1 FROM console_host_group_conditions c WHERE c.asset_group_id = gid)
           AND NOT EXISTS (SELECT 1 FROM console_host_group_conditions c
                           WHERE c.asset_group_id = gid
                             AND NOT COALESCE(console_condition_holds(a, c.field, c.negate, c.vals), false))
          END) $$;

-- Display names of automatic groups; host_group_facts.rs holds the same map
-- and a test compares the two.
CREATE FUNCTION console_os_family_name(os_family text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE os_family WHEN 'linux' THEN 'Linux' WHEN 'windows' THEN 'Windows'
         ELSE upper(left(os_family, 1)) || substr(os_family, 2) END $$;
CREATE FUNCTION console_distribution_name(distribution text) RETURNS text LANGUAGE sql IMMUTABLE AS $$
  SELECT CASE split_part(distribution, ' ', 1)
           WHEN 'debian' THEN 'Debian' WHEN 'ubuntu' THEN 'Ubuntu' WHEN 'fedora' THEN 'Fedora'
           WHEN 'rocky' THEN 'Rocky Linux' WHEN 'almalinux' THEN 'AlmaLinux'
           ELSE upper(left(distribution, 1)) || substr(split_part(distribution, ' ', 1), 2) END
         || substr(distribution, length(split_part(distribution, ' ', 1)) + 1) $$;

-- upgrade (§12 part 4): every asset group becomes a manual group holding the
-- active hosts its tag selectors match now (a group without selectors matched
-- no one and holds no one)
INSERT INTO console_host_group_members (asset_group_id, agent_id, added_at, added_by)
SELECT g.asset_group_id, a.agent_id, now(), 'migration'
FROM console_asset_groups g JOIN agents a ON a.status = 'active'
WHERE EXISTS (SELECT 1 FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id)
  AND NOT EXISTS (SELECT 1 FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id
                  AND NOT EXISTS (SELECT 1 FROM console_agent_tags t WHERE t.agent_id = a.agent_id
                                  AND t.tag_key = s.tag_key AND t.tag_value = s.tag_value));
UPDATE console_asset_groups g SET kind = 'manual', upgraded_from_tags = true, changed_at = now(),
  changed_by = 'migration',
  description = left(COALESCE(
    'Upgraded from an asset group (it used the ' || sel.tags
      || CASE WHEN sel.n > 1 THEN ' tags' ELSE ' tag' END
      || '): the same hosts, now hand-picked. Turn it into a rule when you can.',
    'Upgraded from an asset group without tags, which matched no host. Pick hosts or turn it into a rule.'), 500)
FROM console_asset_groups g2
LEFT JOIN LATERAL (SELECT string_agg(tag_key || '=' || tag_value, ', ' ORDER BY tag_key) AS tags, count(*) AS n
                   FROM console_asset_group_selectors s WHERE s.asset_group_id = g2.asset_group_id) sel ON true
WHERE g2.asset_group_id = g.asset_group_id;
INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id, target_kind, target_id)
SELECT 'migration', 'host_group.migrated', g.name, 'success',
       jsonb_build_object('selectors', COALESCE((SELECT jsonb_agg(tag_key || '=' || tag_value ORDER BY tag_key)
                                                 FROM console_asset_group_selectors s WHERE s.asset_group_id = g.asset_group_id), '[]'),
                          'hosts', (SELECT count(*) FROM console_host_group_members m WHERE m.asset_group_id = g.asset_group_id))
       || CASE WHEN r.old_name IS NULL THEN '{}'::jsonb
               ELSE jsonb_build_object('renamed_from', r.old_name, 'renamed_to', g.name) END,
       'system', 'openvibes', 'host_group', g.asset_group_id::text
FROM console_asset_groups g LEFT JOIN host_group_renamed r USING (asset_group_id);
DROP TABLE host_group_renamed;

-- each tag k=v becomes the label k:v (at most 64 characters); a host whose
-- tags were cut or fell together gets one audit row naming them
INSERT INTO console_host_labels (agent_id, label, added_at, added_by)
SELECT agent_id, left(tag_key || ':' || tag_value, 64), changed_at, changed_by FROM console_agent_tags
ON CONFLICT DO NOTHING;
INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id, target_kind, target_id)
SELECT 'migration', 'host.labels_migrated', agent_id, 'success',
       jsonb_build_object(
         'truncated', COALESCE(jsonb_agg(jsonb_build_object('tag', tag, 'label', label) ORDER BY tag)
                               FILTER (WHERE char_length(tag) > 64), '[]'),
         'merged', COALESCE(jsonb_agg(jsonb_build_object('tag', tag, 'label', label) ORDER BY tag)
                            FILTER (WHERE same > 1), '[]')),
       'system', 'openvibes', 'agent', agent_id
FROM (SELECT agent_id, tag, left(tag, 64) AS label,
             count(*) OVER (PARTITION BY agent_id, left(tag, 64)) AS same
      FROM (SELECT agent_id, tag_key || ':' || tag_value AS tag FROM console_agent_tags) t) l
GROUP BY agent_id
HAVING bool_or(char_length(tag) > 64 OR same > 1);

-- automatic groups for facts already reported, one at a time so each name
-- sees the ones before it
DO $$
DECLARE f record; gid uuid; gname text;
BEGIN
  FOR f IN SELECT DISTINCT 'os_family' AS field, os_family AS val, console_os_family_name(os_family) AS display
           FROM agents WHERE status = 'active' AND os_family IS NOT NULL
           UNION
           SELECT DISTINCT 'distribution', distribution, console_distribution_name(distribution)
           FROM agents WHERE status = 'active' AND distribution IS NOT NULL
           ORDER BY 1 DESC, 2 LOOP
    gid := gen_random_uuid();
    gname := console_free_group_name(f.display, 'automatic');
    INSERT INTO console_asset_groups (asset_group_id, name, created_at, created_by, kind, auto_key, description)
    VALUES (gid, gname, now(), 'openvibes', 'automatic', f.field || ':' || f.val,
            left(CASE f.field WHEN 'os_family' THEN 'Every host that reports ' || f.display || '. Kept up to date by OpenVIBES.'
                              ELSE 'Hosts running ' || f.display || '.' END, 500));
    INSERT INTO console_host_group_conditions (asset_group_id, position, field, negate, vals)
    VALUES (gid, 0, f.field, false, ARRAY[f.val]);
    INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id, target_kind, target_id)
    VALUES ('openvibes', 'host_group.created_automatically', gname, 'success',
            jsonb_build_object('auto_key', f.field || ':' || f.val), 'system', 'openvibes', 'host_group', gid::text);
  END LOOP;
END $$;

DROP TABLE console_agent_tags;
DROP TABLE console_asset_group_selectors;

GRANT SELECT, INSERT, UPDATE, DELETE ON console_host_group_conditions, console_host_group_members, console_host_labels, console_host_group_dismissed TO "openvibes-console";
GRANT UPDATE (kind, description, auto_key, version, changed_at, changed_by, upgraded_from_tags, name) ON console_asset_groups TO "openvibes-console";
GRANT DELETE ON console_asset_groups TO "openvibes-console";
GRANT SELECT ON console_host_group_conditions, console_host_group_members TO "openvibes-distribution";
GRANT SELECT (agent_id, status, os_family, distribution, hostname, last_address) ON agents TO "openvibes-distribution";
GRANT SELECT (asset_group_id, kind) ON console_asset_groups TO "openvibes-distribution";
GRANT INSERT, SELECT ON console_asset_groups, console_host_group_conditions TO "openvibes-ingest";
GRANT SELECT ON console_host_group_dismissed TO "openvibes-ingest";
