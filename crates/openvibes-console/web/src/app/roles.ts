// The built-in roles, for choosing one when granting access. Generated from
// the platform's role table (api/roles.json), so the names always match.
import builtinRoles from "../api/roles.json";

export const roles = builtinRoles.map((r) => [r.role_id, r.display_name] as const);
