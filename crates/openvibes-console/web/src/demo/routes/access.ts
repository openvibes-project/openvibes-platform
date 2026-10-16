// Access: users, role bindings, asset groups and service accounts.
import type { DemoContext } from "../context";
import { json, problem } from "../http";

export function registerAccessRoutes(ctx: DemoContext) {
  const { data, iso, actor, audit, route } = ctx;
  route("GET", "/api/v1/access-control", "access.read", () => json(data.access));
  route("POST", "/api/v1/access-control/users", "access.users", (_, __, body) => {
    const username = String(body.username ?? "").toLowerCase();
    const displayName = String(body.display_name ?? "").trim();
    if (!/^[a-z0-9._@+-]{1,64}$/.test(username) || displayName === "") return problem(400, "invalid_user", "Use 1 to 64 letters, digits or ._@+- for the username, and a name");
    if (data.access.users.some((u) => u.username === username)) return problem(409, "user_conflict", "A user with this username already exists");
    const user = { user_id: `u-${Date.now().toString(36)}`, username, display_name: displayName };
    data.access.users.push(user);
    data.access.bindings.push({ binding_id: `b-${Date.now().toString(36)}`, user_id: user.user_id, username, display_name: displayName, role_id: String(body.role_id ?? "viewer"), asset_group_id: null, asset_group_name: null, created_at: iso(), created_by: actor });
    audit("user.created", user.user_id, "user");
    return json({ ...user, role_id: String(body.role_id ?? "viewer"), one_time_password: "demo1-pass2-word3-onlyx" }, 201);
  });
  route("POST", "/api/v1/access-control/bindings", "access.grant", (_, __, body) => {
    const user = data.access.users.find((u) => u.user_id === body.user_id);
    if (!user) return problem(422, "invalid_user", "Choose a user");
    const group = data.access.asset_groups.find((g) => g.asset_group_id === body.asset_group_id);
    const binding = { binding_id: `b-${Date.now().toString(36)}`, user_id: user.user_id, username: user.username, display_name: user.display_name, role_id: String(body.role_id), asset_group_id: group?.asset_group_id ?? null, asset_group_name: group?.name ?? null, created_at: iso(), created_by: actor };
    data.access.bindings.push(binding);
    audit("access.binding.create", binding.binding_id, "binding");
    return json(binding, 201);
  });
  const saveGroup = (id: string, body: Record<string, unknown>) => {
    const name = String(body.name ?? "").trim();
    const selectors = ((body.selectors ?? []) as { key: string; value: string }[]).map((sel) => `${sel.key}=${sel.value}`);
    if (name === "" || selectors.length === 0 || selectors.some((sel) => /^=|=$/.test(sel))) return undefined;
    return { asset_group_id: id, name, selectors };
  };
  route("POST", "/api/v1/access-control/asset-groups", "host_groups.manage", (_, __, body) => {
    const group = saveGroup(`grp-${Date.now().toString(36)}`, body);
    if (!group) return problem(422, "invalid_asset_group", "Give the group a name and at least one key=value selector");
    data.access.asset_groups.push(group);
    audit("access.asset_group.create", group.asset_group_id, "asset_group");
    return json(group, 201);
  });
  route("PUT", "/api/v1/access-control/asset-groups/{id}", "host_groups.manage", ({ id = "" }, _, body) => {
    const index = data.access.asset_groups.findIndex((g) => g.asset_group_id === id);
    const group = saveGroup(id, body);
    if (index < 0) return problem(404, "not_found", "Asset group not found");
    if (!group) return problem(422, "invalid_asset_group", "Give the group a name and at least one key=value selector");
    data.access.asset_groups[index] = group;
    audit("access.asset_group.update", id, "asset_group");
    return json(group);
  });
  route("DELETE", "/api/v1/access-control/bindings/{id}", "access.grant", ({ id = "" }) => {
    data.access.bindings = data.access.bindings.filter((b) => b.binding_id !== id);
    audit("access.binding.delete", id, "binding");
    return new Response(null, { status: 204 });
  });

  route("GET", "/api/v1/service-accounts", "service_accounts.read", () => json({ items: data.serviceAccounts }));
  route("GET", "/api/v1/service-accounts/{id}/tokens", "service_accounts.read", ({ id = "" }) => json({ items: data.serviceTokens.get(id) ?? [] }));
  route("POST", "/api/v1/service-accounts", "service_accounts.manage", (_, __, body) => {
    const name = String(body.name ?? "").trim();
    if (name === "" || name.length > 128) return problem(422, "invalid_name", "Give the account a name");
    const account = { service_account_id: `sa-${Date.now().toString(36)}`, name, role_ids: [String(body.role_id ?? "viewer")], enabled: true, active_tokens: 0, created_at: iso() };
    data.serviceAccounts.push(account);
    audit("service_account.create", account.service_account_id, "service_account");
    return json(account, 201);
  });
  const issued = new Map<string, { token_id: string; expires_at: string }>();
  route("POST", "/api/v1/service-accounts/{id}/tokens", "service_accounts.tokens", ({ id = "" }, _, body, headers) => {
    const key = headers["idempotency-key"] ?? "";
    if (!/^[\x21-\x7e]{16,128}$/.test(key)) return problem(400, "invalid_idempotency_key", "Provide an Idempotency-Key header between 16 and 128 visible ASCII characters");
    const account = data.serviceAccounts.find((a) => a.service_account_id === id);
    if (!account) return problem(404, "not_found", "Service account not found");
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
    const found = data.serviceTokens.get(id)?.find((t) => t.token_id === token);
    const account = data.serviceAccounts.find((a) => a.service_account_id === id);
    if (!found || !account) return problem(404, "not_found", "Token not found");
    if (!found.revoked) account.active_tokens = Math.max(0, account.active_tokens - 1);
    found.revoked = true;
    audit("service_token.revoke", id, "service_account");
    return json(found);
  });
  route("POST", "/api/v1/service-accounts/{id}/disable", "service_accounts.manage", ({ id = "" }) => {
    const account = data.serviceAccounts.find((a) => a.service_account_id === id);
    if (!account) return problem(404, "not_found", "Service account not found");
    account.enabled = false;
    audit("service_account.disable", id, "service_account");
    return json(account);
  });
}
