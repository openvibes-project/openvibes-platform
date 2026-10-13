-- OpenVIBES platform schema version 49: netlog

INSERT INTO console_permissions (permission_id, scope_class)
VALUES
    ('netlog.read', 'global'),
    ('netlog.manage', 'global');

INSERT INTO console_role_permissions (role_id, permission_id)
VALUES
    ('admin', 'netlog.read'),
    ('admin', 'netlog.manage');

GRANT SELECT ON devices TO "openvibes-console";