INSERT INTO console_permissions (permission_id, scope_class)
VALUES ('assistant.use', 'global');

INSERT INTO console_role_permissions (role_id, permission_id)
VALUES ('analyst', 'assistant.use'), ('admin', 'assistant.use');
