-- openvibes: needs-backup
-- OpenVIBES platform schema version 68: dashboard sharing (roles spec
-- 2026-10-16 §11, step 6). A dashboard is `private`, shared with some of its
-- roles (`roles`, rows in console_dashboard_roles) or with `everyone`.
-- Nobody's access changes: a dashboard that is shared with a role (schema 52
-- moved the old single role into console_dashboard_roles) becomes `roles`;
-- every other dashboard is `private`.
ALTER TABLE console_dashboards
  ADD COLUMN visibility text NOT NULL DEFAULT 'private'
    CHECK (visibility IN ('private','roles','everyone'));
UPDATE console_dashboards d SET visibility = 'roles'
  WHERE EXISTS (SELECT 1 FROM console_dashboard_roles dr WHERE dr.dashboard_id = d.dashboard_id);
CREATE INDEX console_dashboards_everyone_idx ON console_dashboards (dashboard_id)
  WHERE visibility = 'everyone';
