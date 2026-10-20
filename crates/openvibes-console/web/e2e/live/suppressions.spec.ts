// Spec §15, "a suppression approved by the other team lead": with approval
// on, a Linux lead's request waits, they cannot approve it themselves, the
// Windows lead never sees it, the second Linux lead approves it and the alarm
// closes, and the administrator reads it in the audit log. Each browser uses
// its own seeded host (lin-sup-1/2/3, console-e2e-server.sh) and group.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

const LEAD = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
type Row = { id: string; alarm_id: string | null; reason: string };

/** A role with the Team lead template on one new rule group of hostnames matching `pattern`. */
async function leadRole(page: Page, name: string, pattern: string) {
  const group = await api(page, "POST", "/api/v1/host-groups", { name, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [pattern] }] });
  expect(group.status).toBe(201);
  const role = await api(page, "POST", "/api/v1/roles", { name, permissions: LEAD, reach: { kind: "groups", asset_group_ids: [(group.json as { asset_group_id: string }).asset_group_id] } });
  expect(role.status).toBe(201);
  return (role.json as { role_id: string }).role_id;
}

async function person(page: Page, username: string, roleId: string) {
  const created = await api(page, "POST", "/api/v1/users", { username, display_name: `${username} person`, role_ids: [roleId] });
  expect(created.status).toBe(201);
  return (created.json as { one_time_password: string }).one_time_password;
}

test("a suppression waits for approval and the other team lead approves it", async ({ page, browser }, info) => {
  const tag = `${info.project.name}-${Date.now().toString(36)}`;
  const host = `lin-sup-${["chromium", "firefox", "webkit"].indexOf(info.project.name) + 1}`;
  const reason = `nightly backup ${tag}`;
  await signIn(page, "alex");

  // 1. The admin turns approval on (another browser may have already).
  await page.goto("/settings?tab=general");
  const toggle = page.getByRole("switch", { name: "Suppressions need approval" });
  await expect(toggle).toHaveAttribute("aria-checked", /^(true|false)$/);
  if ((await toggle.getAttribute("aria-checked")) === "false") await toggle.click();
  await expect(toggle).toHaveAttribute("aria-checked", "true");

  const linux = await leadRole(page, `Linux leads ${tag}`, `${host}*`);
  const windows = await leadRole(page, `Windows lead ${tag}`, "windows-*");
  const passwords = { a: await person(page, `lead-a-${tag}`, linux), b: await person(page, `lead-b-${tag}`, linux), w: await person(page, `lead-w-${tag}`, windows) };
  const a = await firstSignIn(browser, `lead-a-${tag}`, passwords.a);
  const b = await firstSignIn(browser, `lead-b-${tag}`, passwords.b);
  const w = await firstSignIn(browser, `lead-w-${tag}`, passwords.w);
  try {
    // 2. Lead A suppresses the alarm on their host for the Linux group; it waits.
    await a.goto("/alarms");
    await a.locator(".view tbody tr").filter({ hasText: `Team alarm on ${host}` }).getByRole("button", { name: /^Suppress…/ }).click();
    const form = a.getByRole("dialog", { name: "Suppress alarms like this" });
    await form.getByRole("combobox", { name: "Where" }).click();
    await a.getByRole("option", { name: `Linux leads ${tag}` }).click();
    await form.getByRole("textbox", { name: "Reason (required)" }).fill(reason);
    await form.getByRole("button", { name: "Request" }).click();
    await expect(a.locator(".toast").last()).toContainText("Requested · waiting for approval");

    // 3. A's own Approve is not offered, and the API refuses it.
    await a.goto("/alarm-suppressions");
    const mine = a.locator("#suppressions-waiting [data-id]").filter({ hasText: reason });
    await expect(mine).toContainText("Waiting");
    await expect(mine).toContainText(`Where: Linux leads ${tag}`);
    await expect(mine.getByRole("button", { name: /^Approve/ })).toHaveCount(0);
    await expect(mine.getByRole("button", { name: "Withdraw /usr/local/bin/backup-job" })).toBeVisible();
    const id = (await mine.getAttribute("data-id")) ?? "";
    const own = await api(a, "POST", `/api/v1/alarm-suppressions/${id}/approve`);
    expect(own.status).toBe(409);
    expect((own.json as { code: string }).code).toBe("own_request");

    // 4. The Windows lead does not see it, and cannot approve it.
    const theirs = (await api(w, "GET", "/api/v1/alarm-suppressions?state=waiting")).json as { items: Row[] };
    expect(theirs.items.some((s) => s.id === id)).toBe(false);
    expect((await api(w, "POST", `/api/v1/alarm-suppressions/${id}/approve`)).status).toBe(404);
    await w.goto("/alarm-suppressions");
    await expect(w.getByRole("heading", { name: "Alarm suppressions" })).toBeVisible();
    await expect(w.locator("[data-id]").filter({ hasText: reason })).toHaveCount(0);

    // 5. Lead B approves it, and the alarm is closed.
    await b.goto("/alarm-suppressions");
    const waiting = b.locator("#suppressions-waiting [data-id]").filter({ hasText: reason });
    await waiting.getByRole("button", { name: "Approve /usr/local/bin/backup-job" }).click();
    await expect(b.locator("#suppressions-active [data-id]").filter({ hasText: reason })).toContainText("Active");
    const row = ((await api(b, "GET", "/api/v1/alarm-suppressions")).json as { items: Row[] }).items.find((s) => s.id === id);
    const alarm = (await api(b, "GET", `/api/v1/alarms/${row?.alarm_id}`)).json as { state: string; suppressed_by: string | null };
    expect(alarm.state).toBe("false_positive");
    expect(String(alarm.suppressed_by)).toBe(id);
    await b.goto("/alarms");
    // B's only alarm was that one: the open list is empty.
    await expect(b.getByRole("heading", { name: "Nothing matches these filters" })).toBeVisible();
    await expect(b.getByText(`Team alarm on ${host}`)).toHaveCount(0);

    // 6. The admin sees it in the audit log: approval switched on, requested by A, approved by B.
    const since = encodeURIComponent(new Date(Date.now() - 3_600_000).toISOString());
    const lines = (await api(page, "GET", `/api/v1/audit-events?since=${since}&action_prefix=alarm.suppression.&limit=100`)).json as { items: { action: string; target_id: string | null }[] };
    expect(lines.items.filter((e) => e.target_id === id).map((e) => e.action)).toEqual(["alarm.suppression.approved", "alarm.suppression.requested"]);
    const settings = (await api(page, "GET", `/api/v1/audit-events?since=${since}&action=settings.changed`)).json as { items: unknown[] };
    expect(settings.items.length).toBeGreaterThan(0);
    await page.goto("/alarm-suppressions");
    const recent = page.locator(".person-card").filter({ hasText: "Recent changes" });
    await expect(recent).toContainText(`Approved a suppression #${id}`);
    await expect(recent).toContainText(`Requested a suppression #${id}`);
  } finally {
    for (const member of [a, b, w]) await member.context().close();
  }
});
