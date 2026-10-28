// People and service accounts (access/people*.rs, service_*.rs). Like the
// server, an editor without Administrator sees and changes only people and
// accounts whose roles all fit inside their own share; others are absent.
import type { PersonView } from "../../api/types";
import catalogue from "../../api/permissions.json";
import type { DemoContext } from "../context";
import { demoPictures } from "../../ui/avatar";
import { json, problem } from "../http";
import { ADMIN_ROLE } from "../share";
import type { RoleHelpers } from "./roles";

type AccessLine = PersonView["access"][number];
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

export function registerAccessRoutes(ctx: DemoContext & { roles: RoleHelpers }) {
  const { data, iso, me, permissions, rolesOf, audit, route, roles: { roleView, roleById, refuseOutside, rolesFit } } = ctx;
  type User = (typeof data.access.users)[number];
  const has = (p: string) => permissions.includes(p as (typeof permissions)[number]);
  const denied = (title = "Access is not available") => problem(403, "permission_denied", title);
  const userNotFound = () => problem(404, "user_not_found", "No such person");
  const noContent = () => new Response(null, { status: 204 });

  /** people.rs `visible_person`: yourself, or someone whose roles all fit your share. */
  const visiblePerson = (id: string): User | Response => {
    const user = data.access.users.find((u) => u.user_id === id);
    return user && (user.user_id === me || rolesFit(rolesOf(user.user_id))) ? user : userNotFound();
  };
  const row = (user: User) => ({ ...user, picture: demoPictures.get(user.user_id)?.version ?? null, roles: rolesOf(user.user_id).map(roleView) });
  const accessLines = (userId: string): AccessLine[] => catalogue.flatMap((p) => rolesOf(userId).flatMap((role): AccessLine[] => {
    if (role.role_id !== ADMIN_ROLE && !role.permissions.includes(p.id)) return [];
    const line = { permission: p.id as AccessLine["permission"], label: p.label, area: p.area, from_role: role.name };
    if (p.scope === "platform") return [{ ...line, applies: "platform", groups: [] }];
    const reach = roleView(role).reach;
    if (reach.kind === "all") return [{ ...line, applies: "all", groups: [] }];
    return reach.kind === "groups" ? [{ ...line, applies: "groups", groups: reach.groups }] : [];
  }));
  /** The last enabled Administrator stays (the store's guard). */
  const lastAdmin = (userId: string) => data.access.users.filter((u) => u.enabled && rolesOf(u.user_id).some((r) => r.role_id === ADMIN_ROLE))
    .every((u) => u.user_id === userId);
  const isAdmin = (userId: string) => rolesOf(userId).some((r) => r.role_id === ADMIN_ROLE);
  const lastAdministrator = () => problem(409, "last_administrator", "Someone else must hold Administrator first");

  route("GET", "/api/v1/users", "access.read", () =>
    json(data.access.users.filter((u) => rolesFit(rolesOf(u.user_id))).sort((a, b) => a.display_name.localeCompare(b.display_name)).map(row)));
  route("GET", "/api/v1/users/{id}", null, ({ id = "" }) => {
    if (id !== me && !has("access.read")) return denied();
    const user = visiblePerson(id);
    if (user instanceof Response) return user;
    const recent = data.audit.filter((e) => e.actor_id === id).slice(0, 10).map((e) => ({ action: e.action, target: e.target ?? null, at: e.at }));
    return json({ ...row(user), access: accessLines(id), recent });
  });

  // The demo keeps the chosen picture as it is (no crop, no conversion) and
  // checks only what the server checks first: the person and the permission.
  route("PUT", "/api/v1/users/{id}/picture", null, ({ id = "" }, _, body) => {
    if (id !== me && !has("access.users")) return denied();
    const user = visiblePerson(id);
    if (user instanceof Response) return user;
    const url = typeof body.data_url === "string" ? body.data_url : "";
    if (!url.startsWith("data:image/")) return problem(422, "picture_unsupported", "Use a JPEG, PNG, GIF, WebP, BMP or TIFF picture");
    const version = crypto.randomUUID().replaceAll("-", "").padEnd(64, "0");
    demoPictures.set(id, { version, url });
    audit("user.picture.set", user.username, "user");
    return json({ picture: version });
  });
  route("DELETE", "/api/v1/users/{id}/picture", null, ({ id = "" }) => {
    if (id !== me && !has("access.users")) return denied();
    const user = visiblePerson(id);
    if (user instanceof Response) return user;
    if (demoPictures.delete(id)) audit("user.picture.removed", user.username, "user");
    return noContent();
  });

  const displayName = (value: unknown) => {
    const name = typeof value === "string" ? value.trim() : "";
    return name !== "" && [...name].length <= 160 && !CONTROL.test(name) ? name : null;
  };
  /** people.rs `email`: empty clears; null when invalid. */
  const email = (value: string): { ok: string | null } | null => {
    const address = value.trim();
    if (address === "") return { ok: null };
    const [local = "", domain = "", ...rest] = address.split("@");
    return [...address].length <= 254 && !/\s/.test(address) && !CONTROL.test(address) && local && domain && rest.length === 0 ? { ok: address } : null;
  };
  const invalidEmail = () => problem(422, "invalid_email", "Enter an email address such as name@example.com");

  route("POST", "/api/v1/users", "access.users", (_, __, body) => {
    const raw = typeof body.username === "string" ? body.username : "";
    const name = displayName(body.display_name);
    if (!/^[A-Za-z0-9._@+-]{1,64}$/.test(raw) || name === null) {
      return problem(400, "invalid_user", "Use 1 to 64 letters, digits or ._@+- for the username and 1 to 160 characters for the name");
    }
    const address = typeof body.email === "string" ? email(body.email) : { ok: null };
    if (address === null) return invalidEmail();
    const roleIds = [...new Set(Array.isArray(body.role_ids) ? body.role_ids.map(String) : [])].sort((a, b) => a.localeCompare(b));
    if (roleIds.length === 0 || roleIds.length > 64) return problem(400, "invalid_user", "Give the person 1 to 64 roles");
    for (const id of roleIds) {
      const role = roleById(id);
      if (!role) return problem(400, "unknown_role", "Choose an existing role");
      const refused = refuseOutside(role.permissions, role.reach);
      if (refused) return refused;
    }
    const username = raw.toLowerCase();
    if (data.access.users.some((u) => u.username === username)) return problem(409, "user_conflict", "A user with this username already exists");
    const user: User = { user_id: `u-${crypto.randomUUID()}`, username, display_name: name, email: address.ok, enabled: true, auth_source: "password", last_sign_in_at: null, created_at: iso() };
    data.access.users.push(user);
    for (const roleId of roleIds) data.access.bindings.push({ user_id: user.user_id, role_id: roleId });
    audit("user.created", username, "user");
    return json({ user_id: user.user_id, username, display_name: name, role_ids: roleIds, one_time_password: "demo1-pass2-word3-onlyx" }, 201);
  });
  route("PATCH", "/api/v1/users/{id}", null, ({ id = "" }, _, body) => {
    if (id !== me && !has("access.users")) return denied();
    if (Object.keys(body).some((key) => key !== "display_name" && key !== "email")) return problem(400, "invalid_user", "Send a display name or an email");
    const name = body.display_name === undefined ? undefined : displayName(body.display_name);
    if (name === null) return problem(422, "invalid_user", "Use 1 to 160 characters for the name");
    const address = typeof body.email === "string" ? email(body.email) : undefined;
    if (address === null) return invalidEmail();
    const user = visiblePerson(id);
    if (user instanceof Response) return user;
    if (name !== undefined) user.display_name = name;
    if (address !== undefined) user.email = address.ok;
    audit("user.updated", user.username, "user");
    return noContent();
  });

  /** people_admin.rs `managed`: access.users and the person inside the share. */
  const managed = (id: string) => (has("access.users") ? visiblePerson(id) : denied());
  route("POST", "/api/v1/users/{id}/disable", null, ({ id = "" }) => {
    const user = managed(id);
    if (user instanceof Response) return user;
    if (user.user_id === me) return denied("You cannot disable your own account");
    if (!user.enabled) return noContent();
    if (isAdmin(user.user_id) && lastAdmin(user.user_id)) return lastAdministrator();
    user.enabled = false;
    audit("user.disabled", user.username, "user");
    return noContent();
  });
  route("POST", "/api/v1/users/{id}/enable", null, ({ id = "" }) => {
    const user = managed(id);
    if (user instanceof Response) return user;
    user.enabled = true;
    audit("user.enabled", user.username, "user");
    return noContent();
  });
  route("POST", "/api/v1/users/{id}/reset-password", null, ({ id = "" }) => {
    const user = managed(id);
    if (user instanceof Response) return user;
    if (user.user_id === me) return problem(403, "use_change_password", "Use Change password for your own account");
    audit("user.password_reset", user.username, "user");
    return json({ one_time_password: "demo4-pass5-word6-onlyx" });
  });

  /** people_roles.rs `change` for a person: access.grant, not yourself, the whole role inside the share. */
  const changeRole = (id: string, roleId: string, give: boolean) => {
    if (!has("access.grant")) return denied();
    const user = visiblePerson(id);
    if (user instanceof Response) return user;
    if (user.user_id === me) return denied("Nobody can change their own roles");
    const role = roleById(roleId);
    if (!role) return problem(404, "role_not_found", "No such role");
    const refused = refuseOutside(role.permissions, role.reach);
    if (refused) return refused;
    const held = data.access.bindings.some((b) => b.user_id === id && b.role_id === roleId);
    if (give && !held) {
      data.access.bindings.push({ user_id: id, role_id: roleId });
      audit("rbac.binding.created", `${user.username} · ${role.name}`, "user");
    } else if (!give && held) {
      if (roleId === ADMIN_ROLE && user.enabled && lastAdmin(id)) return lastAdministrator();
      data.access.bindings = data.access.bindings.filter((b) => !(b.user_id === id && b.role_id === roleId));
      audit("rbac.binding.revoked", `${user.username} · ${role.name}`, "user");
    }
    return noContent();
  };
  route("PUT", "/api/v1/users/{id}/roles/{role}", null, ({ id = "", role = "" }) => changeRole(id, role, true));
  route("DELETE", "/api/v1/users/{id}/roles/{role}", null, ({ id = "", role = "" }) => changeRole(id, role, false));

  registerServiceAccountRoutes(ctx);
}

/** Service accounts: each one outside the caller's share is answered as missing. */
function registerServiceAccountRoutes(ctx: DemoContext & { roles: RoleHelpers }) {
  const { data, iso, permissions, audit, route, roles: { roleById, refuseOutside, rolesFit } } = ctx;
  const accountRoles = (account: (typeof data.serviceAccounts)[number]) => account.role_ids.flatMap((id) => roleById(id) ?? []);
  const visibleAccount = (id: string) => {
    const account = data.serviceAccounts.find((a) => a.service_account_id === id);
    return account && rolesFit(accountRoles(account)) ? account : problem(404, "service_account_not_found", "No such service account");
  };
  // The API answers each account's roles by name.
  const accountView = (account: (typeof data.serviceAccounts)[number]) => {
    const { role_ids, ...rest } = account;
    return { ...rest, roles: role_ids.map((id) => ({ role_id: id, name: roleById(id)?.name ?? id })) };
  };
  route("GET", "/api/v1/service-accounts", "service_accounts.read", () => json({ items: data.serviceAccounts.filter((a) => rolesFit(accountRoles(a))).map(accountView) }));
  route("GET", "/api/v1/service-accounts/{id}/tokens", "service_accounts.read", ({ id = "" }) => {
    const account = visibleAccount(id);
    return account instanceof Response ? account : json({ items: data.serviceTokens.get(id) ?? [] });
  });
  route("POST", "/api/v1/service-accounts", "service_accounts.manage", (_, __, body) => {
    const name = String(body.name ?? "").trim();
    const roleIds = [...new Set(Array.isArray(body.role_ids) ? body.role_ids.map(String) : [])].sort((a, b) => a.localeCompare(b));
    if (name === "" || [...name].length > 128 || roleIds.length === 0 || roleIds.length > 64) {
      return problem(400, "invalid_service_account", "Provide a valid name and 1 to 64 roles");
    }
    for (const id of roleIds) {
      const role = roleById(id);
      if (!role) return problem(400, "unknown_role", "Choose an existing role");
      const refused = refuseOutside(role.permissions, role.reach);
      if (refused) return refused;
    }
    if (data.serviceAccounts.some((a) => a.name === name)) return problem(409, "service_account_conflict", "A service account with this name already exists");
    const account = { service_account_id: `sa-${Date.now().toString(36)}`, name, role_ids: roleIds, enabled: true, active_tokens: 0, created_at: iso() };
    data.serviceAccounts.push(account);
    audit("service_account.create", account.service_account_id, "service_account");
    return json(accountView(account), 201);
  });
  const issued = new Map<string, { token_id: string; expires_at: string }>();
  route("POST", "/api/v1/service-accounts/{id}/tokens", "service_accounts.tokens", ({ id = "" }, _, body, headers) => {
    // The server's order: the account's share first, then the key.
    const account = visibleAccount(id);
    if (account instanceof Response) return account;
    const key = headers["idempotency-key"] ?? "";
    if (!/^[\x21-\x7e]{16,128}$/.test(key)) return problem(400, "invalid_idempotency_key", "Provide an Idempotency-Key header between 16 and 128 visible ASCII characters");
    const previous = issued.get(key);
    if (previous) return json({ ...previous, secret_available: false, replayed: true });
    const token = { token_id: `st-${Date.now().toString(36)}${issued.size}`, label: String(body.label ?? ""), created_at: iso(), expires_at: iso(Date.now() + Number(body.expires_in_hours ?? 24) * 3_600_000), revoked: false };
    issued.set(key, { token_id: token.token_id, expires_at: token.expires_at });
    data.serviceTokens.set(id, [token, ...(data.serviceTokens.get(id) ?? [])]);
    account.active_tokens += 1;
    audit("service_token.create", id, "service_account");
    return json({ token_id: token.token_id, token: `ovst_demo_${crypto.randomUUID().replaceAll("-", "")}`, expires_at: token.expires_at, secret_available: true, replayed: false }, 201);
  });
  route("POST", "/api/v1/service-accounts/{id}/tokens/{token}/revoke", "service_accounts.tokens", ({ id = "", token = "" }) => {
    const account = visibleAccount(id);
    if (account instanceof Response) return account;
    const found = data.serviceTokens.get(id)?.find((t) => t.token_id === token);
    if (!found) return problem(404, "not_found", "Token not found");
    if (!found.revoked) account.active_tokens = Math.max(0, account.active_tokens - 1);
    found.revoked = true;
    audit("service_token.revoke", id, "service_account");
    return json(found);
  });
  route("POST", "/api/v1/service-accounts/{id}/disable", "service_accounts.manage", ({ id = "" }) => {
    const account = visibleAccount(id);
    if (account instanceof Response) return account;
    account.enabled = false;
    audit("service_account.disable", id, "service_account");
    return json(account);
  });
  /** people_roles.rs `change` for an account: access.grant and the whole role inside the share. */
  const changeRole = (id: string, roleId: string, give: boolean) => {
    if (!permissions.includes("access.grant")) return problem(403, "permission_denied", "Access is not available");
    const account = visibleAccount(id);
    if (account instanceof Response) return account;
    const role = roleById(roleId);
    if (!role) return problem(404, "role_not_found", "No such role");
    const refused = refuseOutside(role.permissions, role.reach);
    if (refused) return refused;
    const held = account.role_ids.includes(roleId);
    if (give !== held) {
      account.role_ids = give ? [...account.role_ids, roleId].sort((a, b) => a.localeCompare(b)) : account.role_ids.filter((r) => r !== roleId);
      audit(give ? "rbac.binding.created" : "rbac.binding.revoked", `${account.name} · ${role.name}`, "service_account");
    }
    return new Response(null, { status: 204 });
  };
  route("PUT", "/api/v1/service-accounts/{id}/roles/{role}", null, ({ id = "", role = "" }) => changeRole(id, role, true));
  route("DELETE", "/api/v1/service-accounts/{id}/roles/{role}", null, ({ id = "", role = "" }) => changeRole(id, role, false));
}
