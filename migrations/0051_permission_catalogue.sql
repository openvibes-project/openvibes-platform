-- openvibes: needs-backup
-- OpenVIBES platform schema version 51: one permission per action
-- (spec 2026-10-16-roles-permissions-design.md §3, §12 part 1). The new
-- catalogue replaces console_permissions; every role keeps what it could
-- do, mapped to the new ids, plus the needs of what it holds, the export of
-- what it reads, and the new views covering what it could already see.
-- scope_class: 'agent' = host scope, 'global' = platform scope.
CREATE TEMP TABLE permission_map (old_id text, new_id text) ON COMMIT DROP;
INSERT INTO permission_map VALUES
  ('agents.read','hosts.read'), ('agents.read','hosts.export'),
  ('agents.revoke','hosts.revoke'),
  ('cases.manage','cases.write'), ('cases.manage','cases.assign'),
  ('tokens.create','tokens.manage'), ('tokens.create','tokens.installer'),
  ('tokens.revoke','tokens.manage'), ('tokens.revoke','tokens.installer'),
  ('rules.upload','rules.publish'), ('rules.upload','rules.read'),
  ('rules.upload','rules.assignment.read'), ('rules.upload','rules.coverage.read'),
  ('rules.write','rules.assignment.write'), ('rules.write','site_rules.write'),
  ('rules.write','site_rules.test'), ('rules.write','site_rules.publish'),
  ('rules.write','site_rules.read'),
  ('rules.read','rules.read'), ('rules.read','rules.assignment.read'),
  ('rules.read','rules.coverage.read'), ('rules.read','rules.contents.read'),
  ('rbac.read','access.read'),
  ('rbac.manage','access.users'), ('rbac.manage','access.roles'), ('rbac.manage','access.grant'),
  ('asset_groups.manage','host_groups.manage'),
  ('service_accounts.manage','service_accounts.manage'),
  ('service_accounts.manage','service_accounts.tokens'),
  ('alarms.read','alarms.read'), ('alarms.read','alarms.suppressions.read'),
  ('alarms.read','alarms.export'),
  ('compliance.read','compliance.read'), ('compliance.read','compliance.export'),
  ('vulnerabilities.read','vulnerabilities.read'),
  ('vulnerabilities.read','vulnerabilities.export');
-- Every other old id maps to itself.
INSERT INTO permission_map
SELECT permission_id, permission_id FROM console_permissions
WHERE permission_id NOT IN (SELECT old_id FROM permission_map);

INSERT INTO console_permissions (permission_id, scope_class) VALUES
  ('alarms.read','agent'),
  ('alarms.suppressions.read','agent'),
  ('alarms.triage','agent'),
  ('alarms.suppress','agent'),
  ('alarms.export','agent'),
  ('alarms.suppressions.approve','agent'),
  ('compliance.read','agent'),
  ('compliance.triage','agent'),
  ('compliance.export','agent'),
  ('vulnerabilities.read','agent'),
  ('vulnerabilities.triage','agent'),
  ('vulnerabilities.export','agent'),
  ('hosts.read','agent'),
  ('hosts.label','agent'),
  ('hosts.revoke','agent'),
  ('hosts.export','agent'),
  ('cases.read','agent'),
  ('cases.write','agent'),
  ('cases.assign','agent'),
  ('rules.read','global'),
  ('rules.assignment.read','global'),
  ('rules.coverage.read','global'),
  ('rules.contents.read','global'),
  ('rules.assignment.write','global'),
  ('rules.publish','global'),
  ('site_rules.read','global'),
  ('site_rules.write','global'),
  ('site_rules.test','global'),
  ('site_rules.publish','global'),
  ('dashboards.share','global'),
  ('dashboards.publish','global'),
  ('assistant.use','agent'),
  ('assistant.admin','global'),
  ('access.read','global'),
  ('access.users','global'),
  ('access.roles','global'),
  ('access.grant','global'),
  ('host_groups.manage','global'),
  ('service_accounts.read','global'),
  ('service_accounts.manage','global'),
  ('service_accounts.tokens','global'),
  ('tokens.read','global'),
  ('tokens.manage','global'),
  ('tokens.installer','global'),
  ('audit.read','global'),
  ('audit.retention.manage','global'),
  ('audit.export','global'),
  ('settings.manage','global')
ON CONFLICT (permission_id) DO UPDATE SET scope_class = EXCLUDED.scope_class;

CREATE TEMP TABLE mapped ON COMMIT DROP AS
SELECT DISTINCT rp.role_id, m.new_id AS permission_id
FROM console_role_permissions rp JOIN permission_map m ON m.old_id = rp.permission_id;
DELETE FROM console_role_permissions WHERE permission_id IN (SELECT old_id FROM permission_map);
INSERT INTO console_role_permissions (role_id, permission_id)
SELECT role_id, permission_id FROM mapped;

-- Needs, closed: the deepest chain is three steps, so three passes.
CREATE TEMP TABLE needs (permission_id text, needs text) ON COMMIT DROP;
INSERT INTO needs VALUES
  ('alarms.suppressions.read','alarms.read'),
  ('alarms.triage','alarms.read'),
  ('alarms.suppress','alarms.read'),
  ('alarms.suppress','alarms.suppressions.read'),
  ('alarms.export','alarms.read'),
  ('alarms.suppressions.approve','alarms.suppressions.read'),
  ('compliance.triage','compliance.read'),
  ('compliance.export','compliance.read'),
  ('vulnerabilities.triage','vulnerabilities.read'),
  ('vulnerabilities.export','vulnerabilities.read'),
  ('hosts.label','hosts.read'),
  ('hosts.revoke','hosts.read'),
  ('hosts.export','hosts.read'),
  ('cases.write','cases.read'),
  ('cases.assign','cases.write'),
  ('rules.assignment.read','rules.read'),
  ('rules.contents.read','rules.read'),
  ('rules.assignment.write','rules.assignment.read'),
  ('rules.publish','rules.read'),
  ('site_rules.write','site_rules.read'),
  ('site_rules.test','site_rules.write'),
  ('site_rules.test','hosts.read'),
  ('site_rules.publish','site_rules.write'),
  ('dashboards.publish','dashboards.share'),
  ('access.users','access.read'),
  ('access.roles','access.read'),
  ('access.grant','access.read'),
  ('host_groups.manage','access.read'),
  ('host_groups.manage','hosts.read'),
  ('service_accounts.manage','service_accounts.read'),
  ('service_accounts.tokens','service_accounts.read'),
  ('tokens.manage','tokens.read'),
  ('tokens.installer','tokens.read'),
  ('audit.retention.manage','audit.read'),
  ('audit.export','audit.read');
INSERT INTO console_role_permissions
SELECT rp.role_id, n.needs FROM console_role_permissions rp JOIN needs n USING (permission_id)
ON CONFLICT DO NOTHING;
INSERT INTO console_role_permissions
SELECT rp.role_id, n.needs FROM console_role_permissions rp JOIN needs n USING (permission_id)
ON CONFLICT DO NOTHING;
INSERT INTO console_role_permissions
SELECT rp.role_id, n.needs FROM console_role_permissions rp JOIN needs n USING (permission_id)
ON CONFLICT DO NOTHING;

-- The administrator holds everything.
INSERT INTO console_role_permissions
SELECT 'admin', permission_id FROM console_permissions
WHERE EXISTS (SELECT 1 FROM console_roles WHERE role_id = 'admin')
ON CONFLICT DO NOTHING;

-- The old ids go; their role rows were replaced above.
DELETE FROM console_permissions WHERE permission_id NOT IN (
  'alarms.read', 'alarms.suppressions.read', 'alarms.triage',
  'alarms.suppress', 'alarms.export', 'alarms.suppressions.approve',
  'compliance.read', 'compliance.triage', 'compliance.export',
  'vulnerabilities.read', 'vulnerabilities.triage',
  'vulnerabilities.export', 'hosts.read', 'hosts.label', 'hosts.revoke',
  'hosts.export', 'cases.read', 'cases.write', 'cases.assign', 'rules.read',
  'rules.assignment.read', 'rules.coverage.read', 'rules.contents.read',
  'rules.assignment.write', 'rules.publish', 'site_rules.read',
  'site_rules.write', 'site_rules.test', 'site_rules.publish',
  'dashboards.share', 'dashboards.publish', 'assistant.use',
  'assistant.admin', 'access.read', 'access.users', 'access.roles',
  'access.grant', 'host_groups.manage', 'service_accounts.read',
  'service_accounts.manage', 'service_accounts.tokens', 'tokens.read',
  'tokens.manage', 'tokens.installer', 'audit.read',
  'audit.retention.manage', 'audit.export', 'settings.manage'
);
