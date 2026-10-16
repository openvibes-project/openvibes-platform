-- openvibes: needs-backup
-- OpenVIBES platform schema version 52: custom roles with a host reach
-- (spec 2026-10-16-roles-permissions-design.md §4, §12 parts 2–3).
-- Nobody's access changes: a role reaches all hosts, some groups, or none;
-- scoped bindings become roles that carry their groups.
ALTER TABLE console_roles
  ADD COLUMN description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 500),
  ADD COLUMN all_hosts boolean NOT NULL DEFAULT false,
  ADD COLUMN version integer NOT NULL DEFAULT 1 CHECK (version > 0),
  ADD COLUMN created_at timestamptz NOT NULL DEFAULT now(),
  ADD COLUMN created_by text NOT NULL DEFAULT 'migration',
  ADD CONSTRAINT console_roles_name_length CHECK (char_length(display_name) BETWEEN 1 AND 64);
CREATE TABLE console_role_groups (
  role_id text NOT NULL REFERENCES console_roles ON DELETE CASCADE,
  asset_group_id uuid NOT NULL REFERENCES console_asset_groups ON DELETE RESTRICT,
  PRIMARY KEY (role_id, asset_group_id));
-- Dashboards are shared with roles through this table (one or more roles;
-- shared_role_id is copied here and dropped below).
CREATE TABLE console_dashboard_roles (
  dashboard_id uuid NOT NULL REFERENCES console_dashboards ON DELETE CASCADE,
  role_id text NOT NULL REFERENCES console_roles ON DELETE CASCADE,
  PRIMARY KEY (dashboard_id, role_id));
-- A role with no active binding may be deleted; its revoked history goes
-- with it (the audit log keeps the record).
ALTER TABLE console_role_bindings DROP CONSTRAINT console_role_bindings_role_id_fkey,
  ADD CONSTRAINT console_role_bindings_role_id_fkey FOREIGN KEY (role_id)
    REFERENCES console_roles ON DELETE CASCADE;

-- part 2: built-in roles
UPDATE console_roles SET display_name = 'Administrator', all_hosts = true WHERE role_id = 'admin';
UPDATE console_roles SET builtin = false, all_hosts = true WHERE role_id IN ('viewer','analyst','operator');
CREATE UNIQUE INDEX console_roles_name_unique ON console_roles (lower(display_name));

-- part 3: a holder's scoped bindings of one role, as one set of groups
CREATE TEMP TABLE scoped ON COMMIT DROP AS
  SELECT b.user_id, b.service_account_id, b.role_id,
         array_agg(b.asset_group_id ORDER BY g.name) AS groups,
         string_agg(g.name, ', ' ORDER BY g.name) AS names
  FROM console_role_bindings b JOIN console_asset_groups g USING (asset_group_id)
  WHERE b.revoked_at IS NULL AND b.asset_group_id IS NOT NULL
  GROUP BY b.user_id, b.service_account_id, b.role_id;
CREATE TEMP TABLE new_roles ON COMMIT DROP AS
  SELECT DISTINCT ON (s.role_id, s.groups) s.role_id AS old_role, s.groups,
         'r_' || substr(md5(s.role_id || array_to_string(s.groups, ',')), 1, 16) AS new_role,
         left(r.display_name || ' (' || s.names || ')', 64) AS base, NULL::text AS name
  FROM scoped s JOIN console_roles r USING (role_id);
-- A name that would clash (only possible once shortened to 64 characters)
-- gets " 2", " 3", …
UPDATE new_roles n SET name = CASE WHEN k.nth = 1 THEN n.base
    ELSE left(n.base, 64 - length(' ' || k.nth)) || ' ' || k.nth END
  FROM (SELECT x.new_role, row_number() OVER (PARTITION BY lower(x.base) ORDER BY x.new_role)
               + (SELECT count(*) FROM console_roles r WHERE lower(r.display_name) = lower(x.base)) AS nth
        FROM new_roles x) k
  WHERE k.new_role = n.new_role;
INSERT INTO console_roles (role_id, display_name, builtin, all_hosts)
  SELECT new_role, name, false, false FROM new_roles;
INSERT INTO console_role_groups SELECT new_role, unnest(groups) FROM new_roles;
-- As before, only the old agent-bound permissions applied on the group.
INSERT INTO console_role_permissions (role_id, permission_id)
  SELECT n.new_role, rp.permission_id FROM new_roles n
  JOIN console_role_permissions rp ON rp.role_id = n.old_role
  JOIN console_permissions p USING (permission_id) WHERE p.scope_class = 'agent';
-- move bindings: one binding to the new role, the scoped ones revoked; the
-- audit log keeps where each came from (the column is dropped below)
INSERT INTO console_role_bindings (binding_id, user_id, service_account_id, role_id, asset_group_id, created_at, created_by)
  SELECT gen_random_uuid(), s.user_id, s.service_account_id, n.new_role, NULL, now(), 'migration'
  FROM scoped s JOIN new_roles n ON n.old_role = s.role_id AND n.groups = s.groups;
INSERT INTO audit_log (actor, action, target, result, detail, actor_kind, actor_id,
    actor_display, target_kind, target_id)
  SELECT 'migration', 'rbac.binding.migrated', 'role_binding', 'success',
         jsonb_build_object('old_role', b.role_id, 'asset_group_id', b.asset_group_id::text,
                            'groups', to_jsonb(n.groups::text[]), 'new_role', n.new_role),
         'system', 'migration', 'migration', 'role_binding', b.binding_id::text
  FROM console_role_bindings b
  JOIN scoped s ON s.role_id = b.role_id
    AND s.user_id IS NOT DISTINCT FROM b.user_id
    AND s.service_account_id IS NOT DISTINCT FROM b.service_account_id
  JOIN new_roles n ON n.old_role = s.role_id AND n.groups = s.groups
  WHERE b.revoked_at IS NULL AND b.asset_group_id IS NOT NULL;
UPDATE console_role_bindings SET revoked_at = now(), revoked_by = 'migration'
  WHERE revoked_at IS NULL AND asset_group_id IS NOT NULL;

-- dashboards: still shared with the role, and with every role its scoped
-- holders moved to, so nobody loses a dashboard they could see
INSERT INTO console_dashboard_roles (dashboard_id, role_id)
  SELECT dashboard_id, shared_role_id FROM console_dashboards WHERE shared_role_id IS NOT NULL
  UNION
  SELECT d.dashboard_id, n.new_role FROM console_dashboards d
  JOIN new_roles n ON n.old_role = d.shared_role_id;
ALTER TABLE console_dashboards DROP COLUMN shared_role_id;

-- unused built-ins go (their dashboard shares go with them; the shares
-- copied to the roles their scoped holders moved to stay)
DELETE FROM console_roles r WHERE r.role_id IN ('viewer','analyst','operator')
  AND NOT EXISTS (SELECT 1 FROM console_role_bindings b WHERE b.role_id = r.role_id AND b.revoked_at IS NULL);

-- bindings no longer carry a scope
DROP INDEX console_role_bindings_active_unique_idx;
ALTER TABLE console_role_bindings DROP CONSTRAINT console_role_bindings_group_fk;
ALTER TABLE console_role_bindings DROP COLUMN asset_group_id;
CREATE UNIQUE INDEX console_role_bindings_active_unique_idx ON console_role_bindings
  (user_id, service_account_id, role_id) NULLS NOT DISTINCT WHERE revoked_at IS NULL;

-- people
ALTER TABLE console_users
  ADD COLUMN email text CHECK (email IS NULL OR (char_length(email) <= 254 AND email ~ '^[^@\s]+@[^@\s]+$')),
  ADD COLUMN auth_source text NOT NULL DEFAULT 'password' CHECK (auth_source IN ('password','sso')),
  ADD COLUMN last_sign_in_at timestamptz;
-- a person's recent activity (People › person page)
CREATE INDEX audit_log_actor_recent_idx ON audit_log (actor_id, at DESC);

GRANT SELECT, INSERT, UPDATE, DELETE ON console_roles, console_role_permissions, console_role_groups TO "openvibes-console";
GRANT SELECT, INSERT, DELETE ON console_dashboard_roles TO "openvibes-console";
GRANT UPDATE (email, display_name, last_sign_in_at) ON console_users TO "openvibes-console";
