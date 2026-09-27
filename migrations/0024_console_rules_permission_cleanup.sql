-- The user's 2026-09-25 decision makes rules.read Admin-only (recorded in
-- status.md). Remove the stale non-admin grants seeded by migration 0017 so
-- the database role grants match the canonical Rust role table.
DELETE FROM console_role_permissions
WHERE permission_id = 'rules.read'
  AND role_id IN ('viewer', 'analyst', 'operator');
