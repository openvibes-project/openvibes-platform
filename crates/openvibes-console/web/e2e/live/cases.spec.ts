// The Cases list and a case's page on the real console (roles step 5d): a
// team lead reaching only case-P-* (console-e2e-server.sh: case-P-1, case-P-2
// and caseout-P-1 with one alarm each, per browser P) sees only the cases with
// an item on their hosts plus their own, the list's counts agree with its
// rows and leave out the hidden item, and on a case's page they set an
// outcome, close the case with a note and reopen it. Every case carries this
// run's tag, so a retry (CI's retries: 1) or a second run on the same server
// only meets its own; the seeded alarms are taken out of open cases first and
// last, as an alarm sits in one open case at a time.
import { type Page, expect, test } from "@playwright/test";

import templates from "../../src/api/templates.json" with { type: "json" };
import { api, firstSignIn, signIn } from "./helpers";

type Count = { value: string; count: number };
type Row = {
  case_id: string; number: number; title: string; status: string; host_count: number; hosts: { hostname: string | null }[];
  kinds: { alarms: number }; with_outcome: number; takes_outcome: number; ready: boolean; assignee: unknown;
};
type List = {
  total: number; items: Row[];
  summary: { open: number; investigating: number; unassigned: number; ready_to_close: number };
  counts: { status: Count[]; contains: Count[] };
};
type Detail = { case_id: string; number: number; items: { item_id: string; hostname: string | null }[] };

const rows = (page: Page) => page.getByRole("table", { name: "Cases" }).locator("tbody tr");
const card = (page: Page, title: RegExp) => page.locator(".person-card").filter({ has: page.getByRole("heading", { name: title }) });
const actions = (page: Page) => page.locator(".person-page__actions");
const BROWSER: Record<string, number> = { chromium: 1, firefox: 2, webkit: 3 };
const countOf = (counts: Count[], value: string) => counts.find((c) => c.value === value)?.count ?? 0;

test("a team lead's Cases hold only cases on their hosts and their own, and a case's page sets an outcome, closes and reopens", async ({ page, browser }, info) => {
  const p = info.project.name;
  expect(BROWSER[p]).toBeDefined();
  const tag = `${p}-${Date.now().toString(36)}`;
  await signIn(page, "alex");
  const alarmOn = async (host: string) => {
    const list = (await api(page, "GET", `/api/v1/alarm-list?limit=100&q=${host}.example.test`)).json as { items: { id: number; host: { name: string | null } }[] };
    const found = list.items.filter((a) => a.host.name === `${host}.example.test`);
    expect(found).toHaveLength(1);
    return String(found[0]?.id);
  };
  const [mine1, mine2, out] = [await alarmOn(`case-${p}-1`), await alarmOn(`case-${p}-2`), await alarmOn(`caseout-${p}-1`)];
  // Takes the seeded alarms out of any open case, so a retry can add them again.
  const free = async () => {
    for (const ref of [mine1, mine2, out]) {
      const held = (await api(page, "GET", `/api/v1/cases/for-item?kind=alarm&ref=${ref}`)).json as { items: { case: { case_id: string }; item_id: string }[] };
      for (const h of held.items) expect((await api(page, "DELETE", `/api/v1/cases/${h.case.case_id}/items/${h.item_id}`)).status).toBe(204);
    }
  };
  await free();
  const createCase = async (who: Page, title: string, items: { kind: string; ref: string }[]) => {
    const r = await api(who, "POST", "/api/v1/cases", { title: `Cases ${tag} ${title}`, items });
    expect(r.status).toBe(201);
    return r.json as Detail;
  };
  // Partly out of reach: the lead sees case-P-1's alarm, not caseout-P-1's, which already has an outcome.
  const shared = await createCase(page, "shared", [{ kind: "alarm", ref: mine1 }, { kind: "alarm", ref: out }]);
  const hidden = shared.items.find((i) => i.hostname === `caseout-${p}-1.example.test`);
  expect((await api(page, "PUT", `/api/v1/cases/${shared.case_id}/items/${hidden?.item_id}/outcome`, { outcome: "expected", note: "Our own fetch job." })).status).toBe(200);
  const second = await createCase(page, "second", [{ kind: "alarm", ref: mine2 }]);
  const outside = await createCase(page, "outside", [{ kind: "host", ref: `agent.00000000-0000-4000-8000-0000000003${BROWSER[p]}3` }]);
  const empty = await createCase(page, "empty", []);

  const created = await api(page, "POST", "/api/v1/host-groups", {
    name: `cases ${tag}`, kind: "rule", conditions: [{ field: "hostname", negate: false, values: [`case-${p}-*`] }],
  });
  expect(created.status).toBe(201);
  const group = (created.json as { asset_group_id: string }).asset_group_id;
  const permissions = templates.find((t) => t.name === "Team lead")?.permissions ?? [];
  const role = await api(page, "POST", "/api/v1/roles", { name: `Cases lead ${tag}`, permissions, reach: { kind: "groups", asset_group_ids: [group] } });
  expect(role.status).toBe(201);
  const user = await api(page, "POST", "/api/v1/users", {
    username: `cases-lead-${tag}`, display_name: "Cases lead", role_ids: [(role.json as { role_id: string }).role_id],
  });
  expect(user.status).toBe(201);
  const lead = await firstSignIn(browser, `cases-lead-${tag}`, (user.json as { one_time_password: string }).one_time_password);
  try {
    const own = await createCase(lead, "own", []);

    // 1. Only the cases with an item on case-P-* and the lead's own; the others answer 404.
    const list = (await api(lead, "GET", `/api/v1/case-list?q=${encodeURIComponent(tag)}&limit=100`)).json as List;
    expect(list.items.map((r) => r.case_id).sort()).toEqual([shared.case_id, second.case_id, own.case_id].sort());
    for (const c of [outside, empty]) expect((await api(lead, "GET", `/api/v1/cases/${c.case_id}/summary`)).status).toBe(404);
    // The shared case counts only the visible item and host; close still waits on nothing hidden.
    const row = list.items.find((r) => r.case_id === shared.case_id);
    expect([row?.host_count, row?.hosts.map((h) => h.hostname), row?.kinds.alarms, row?.with_outcome, row?.takes_outcome, row?.ready])
      .toEqual([1, [`case-${p}-1.example.test`], 1, 0, 1, false]);
    // The counts agree with the rows.
    expect(list.total).toBe(list.items.length);
    expect(list.summary).toEqual({
      open: list.items.filter((r) => r.status === "open").length, investigating: 0,
      unassigned: list.items.filter((r) => !r.assignee).length, ready_to_close: list.items.filter((r) => r.ready).length,
    });
    expect(countOf(list.counts.status, "open")).toBe(3);
    expect(countOf(list.counts.contains, "alarms")).toBe(2);

    await lead.goto(`/cases?q=${encodeURIComponent(tag)}`);
    await expect(rows(lead)).toHaveCount(3);
    await expect(lead.locator(".summary-line")).toContainText("3 open");
    const listRow = rows(lead).filter({ has: lead.locator(`a[href="/cases/${shared.case_id}"]`) });
    await expect(listRow).toContainText("0/1 with an outcome");
    await expect(rows(lead).filter({ hasText: "caseout" })).toHaveCount(0);

    // 2. The case's page, opened from its row: one item, the hidden one left out.
    await listRow.locator(`a[href="/cases/${shared.case_id}"]`).click();
    await expect(lead).toHaveURL(new RegExp(`/cases/${shared.case_id}$`));
    await expect(lead.getByRole("heading", { level: 1 })).toContainText(`C-${shared.number}`);
    const table = card(lead, /^Items/);
    await expect(table.locator("tr.case-row")).toHaveCount(1);
    await expect(table).not.toContainText("caseout");

    // 3. An outcome, then close with a note, then reopen.
    await table.getByRole("combobox", { name: /^Outcome for/ }).click();
    await lead.getByRole("option", { name: "False positive" }).click();
    await table.getByRole("textbox", { name: /^Note for/ }).fill("A scheduled download.");
    await table.getByRole("button", { name: "Save outcome" }).click();
    await expect(lead.locator(".toast").filter({ hasText: "Outcome saved" })).toBeVisible();
    await expect(lead.locator(".detail-tiles")).toContainText("Ready to close");
    await actions(lead).getByRole("button", { name: "Close case…" }).click();
    const dialog = lead.getByRole("dialog", { name: `Close C-${shared.number}` });
    await dialog.getByLabel("Closing note").fill("Both downloads are ours.");
    await dialog.getByRole("button", { name: "Close case" }).click();
    await expect(lead.locator(".toast").filter({ hasText: "Case closed" })).toBeVisible();
    await expect(lead.locator(".person-page__head")).toContainText("Closed");
    await expect(card(lead, /^Details/)).toContainText("Both downloads are ours.");
    await actions(lead).getByRole("button", { name: "More actions" }).click();
    await lead.getByRole("menuitem", { name: "Reopen" }).click();
    await expect(lead.locator(".toast").filter({ hasText: "Case reopened" })).toBeVisible();
    await expect(actions(lead).getByRole("button", { name: "Close case…" })).toBeVisible();

    // 4. The list row follows.
    await lead.goto(`/cases?q=${encodeURIComponent(tag)}`);
    await expect(listRow).toContainText("1/1 with an outcome");
    await expect(listRow).toContainText("Ready to close");
  } finally {
    await lead.context().close();
    await free();
  }
});
