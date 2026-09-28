-- OpenVIBES platform schema version 26: user dashboards. A dashboard stores
-- only a layout of widgets; every widget reads through the permission-
-- checked console API with the viewer's own scope.
CREATE TABLE console_dashboards (
    dashboard_id uuid PRIMARY KEY,
    owner_user_id uuid NOT NULL REFERENCES console_users ON DELETE CASCADE,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 80),
    layout jsonb NOT NULL CHECK (jsonb_typeof(layout) = 'object' AND octet_length(layout::text) <= 65536),
    shared_role_id text NULL REFERENCES console_roles ON DELETE SET NULL,
    version integer NOT NULL DEFAULT 1 CHECK (version > 0),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);
CREATE INDEX console_dashboards_owner_idx ON console_dashboards (owner_user_id);
CREATE INDEX console_dashboards_shared_idx ON console_dashboards (shared_role_id)
    WHERE shared_role_id IS NOT NULL;

CREATE TABLE console_user_home (
    user_id uuid PRIMARY KEY REFERENCES console_users ON DELETE CASCADE,
    dashboard_id uuid NOT NULL REFERENCES console_dashboards ON DELETE CASCADE
);

INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('dashboards.share', 'global')
ON CONFLICT (permission_id) DO NOTHING;
INSERT INTO console_role_permissions (role_id, permission_id)
VALUES ('admin', 'dashboards.share')
ON CONFLICT DO NOTHING;

GRANT SELECT, INSERT, UPDATE, DELETE ON console_dashboards, console_user_home
    TO "openvibes-console";
