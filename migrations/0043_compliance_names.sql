-- openvibes: needs-backup
-- OpenVIBES platform schema version 43: rule results are "compliance
-- findings" (user, 2026-10-07). Renames the console's stored IDs; the
-- agent wire protocol and the findings tables keep their names. Audit rows
-- and case events are history and are not rewritten.
INSERT INTO console_permissions (permission_id, scope_class) VALUES
    ('compliance.read', 'agent'), ('compliance.triage', 'agent');
INSERT INTO console_role_permissions (role_id, permission_id)
SELECT role_id, replace(permission_id, 'findings.', 'compliance.')
FROM console_role_permissions
WHERE permission_id IN ('findings.read', 'findings.triage');
DELETE FROM console_permissions WHERE permission_id IN ('findings.read', 'findings.triage');

UPDATE console_dashboards d
SET layout = jsonb_set(d.layout, '{widgets}', (
        SELECT COALESCE(jsonb_agg(
            CASE WHEN jsonb_typeof(w->'config') = 'object' THEN jsonb_set(w, '{config}', COALESCE((
                SELECT jsonb_object_agg(k, CASE
                    WHEN k = 'metric' AND v #>> '{}' LIKE 'findings.open.%'
                        THEN to_jsonb('compliance.open.' || substr(v #>> '{}', 15))
                    WHEN k = 'source' AND v = '"findings"' THEN '"compliance"'::jsonb
                    WHEN k = 'view' AND v = '"/findings"' THEN '"/compliance"'::jsonb
                    WHEN k = 'include' AND jsonb_typeof(v) = 'array' THEN COALESCE((
                        SELECT jsonb_agg(CASE WHEN e = '"findings"' THEN '"compliance"'::jsonb ELSE e END ORDER BY i)
                        FROM jsonb_array_elements(v) WITH ORDINALITY AS x(e, i)), '[]'::jsonb)
                    ELSE v END)
                FROM jsonb_each(w->'config') AS c(k, v)), '{}'::jsonb))
            ELSE w END ORDER BY n), '[]'::jsonb)
        FROM jsonb_array_elements(d.layout->'widgets') WITH ORDINALITY AS t(w, n))),
    version = d.version + 1
WHERE jsonb_typeof(d.layout->'widgets') = 'array';

ALTER TABLE case_items DROP CONSTRAINT case_items_kind_check;
UPDATE case_items SET kind = 'compliance_finding' WHERE kind = 'finding';
ALTER TABLE case_items ADD CONSTRAINT case_items_kind_check
    CHECK (kind IN ('alarm', 'compliance_finding', 'vulnerability', 'host', 'software'));
