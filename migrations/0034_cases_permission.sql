-- OpenVIBES platform schema version 34: added a new permission for the cases view, so that analysts and admins can see it.
INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('cases.read', 'agent')
ON CONFLICT (permission_id) DO NOTHING;
INSERT INTO console_role_permissions (role_id, permission_id)
VALUES ('analyst', 'cases.read'),
       ('admin', 'cases.read')
ON CONFLICT DO NOTHING;