// Alarm suppressions with approval, as the store decides them
// (platform-store alarm_suppressions.rs and alarm_suppression_writes.rs):
// a request from one alarm, waiting or active by the approval setting,
// decided by someone else within their approve reach, withdrawn by the
// requester, removed within the suppress reach, and ended by a group's
// delete. Activation closes the source alarm as ingest would. Rows are kept
// in browser storage so every persona sees the same ones.
import type { AlarmSuppression, Permission } from "../api/types";
import type { DemoContext } from "./context";
import { inGroup } from "./hostGroups";
import { browserPersistence } from "./http";

const DAY = 86_400_000;
type State = "waiting" | "active" | "rejected" | "withdrawn" | "removed";
type Stored = {
  id: string; rule_set_id: string; rule_id: string; what: "program" | "command"; exe: string;
  /** The source alarm's args, for `command`; the server keeps their SHA-256. */
  args: string[] | null;
  agent_id: string | null; group_id: string | null; for_days: number | null; state: State; reason: string;
  created_by: string; created_at: string; decided_by: string | null; decided_at: string | null; decision_reason: string | null;
  activated_at: string | null; expires_at: string | null; alarm_id: string | null;
};
/** A store refusal: the route's status, code and (422) field. */
export type Refusal = { status: number; code: string; field?: string };
export type Request = { alarmId: string; what: "program" | "command"; where: { kind: "host" } | { kind: "group"; group_id: string } | { kind: "all" }; forDays: number | null; reason: string };

const notFound: Refusal = { status: 404, code: "suppression_not_found" };
const invalid = (field: string): Refusal => ({ status: 422, code: "invalid_suppression", field });
const validReason = (r: string) => r.length > 0 && [...r].length <= 4000;

export function createSuppressions(ctx: DemoContext, requireApproval: () => boolean) {
  const { data, capabilities, me, actor, iso, audit, reaches, facts } = ctx;
  const storage = browserPersistence("openvibes.v2.demo.suppressions");
  const loaded = storage?.load();
  // What storage holds could be anything: only rows with an id and a state are taken.
  const rows: Stored[] = Array.isArray(loaded) ? (loaded as Stored[]).filter((r) => typeof r?.id === "string" && typeof r.state === "string") : [];
  const save = () => storage?.save(rows);
  const scope = (permission: Permission) => capabilities.find((c) => c.permission === permission)?.scope;
  const groupOf = (id: string | null) => data.access.host_groups.find((g) => g.asset_group_id === id);
  const nameOf = (userId: string | null) => {
    const user = data.access.users.find((u) => u.user_id === userId);
    return user ? user.display_name || user.username : userId;
  };
  /** in_reach: global, a host the scope reaches, a group in it, or (`allRows`) an all-hosts row. */
  const inReach = (permission: Permission, s: Stored, allRows: boolean) => {
    const sc = scope(permission);
    if (!sc) return false;
    if (sc.kind === "global") return true;
    if (s.agent_id) return reaches(permission, s.agent_id);
    if (s.group_id) return sc.asset_group_ids.includes(s.group_id);
    return allRows;
  };
  const expired = (s: Stored) => s.state === "active" && s.expires_at !== null && Date.parse(s.expires_at) <= ctx.now;
  /** Whether `s`'s what and where cover an alarm (ingest's matcher, without state or expiry). */
  const covers = (s: Stored, alarm: (typeof data.alarms)[number]) => {
    const agent = data.agents.find((a) => a.id === alarm.agent_id);
    const group = groupOf(s.group_id);
    return alarm.rule_set_id === s.rule_set_id && alarm.rule_id === s.rule_id && alarm.exe === s.exe
      && (s.what === "program" || JSON.stringify(alarm.process.args) === JSON.stringify(s.args))
      && (!s.agent_id || s.agent_id === alarm.agent_id) && (!s.group_id || (!!agent && !!group && inGroup(facts(agent), group)));
  };
  /** Alarms of the last 7 days on hosts the reader reaches that a waiting row would have closed. */
  const wouldClose = (s: Stored) => data.alarms.filter((a) => Date.parse(a.last_seen) > ctx.now - 7 * DAY
    && reaches("alarms.suppressions.read", a.agent_id) && covers(s, a)).length;

  const view = (s: Stored): AlarmSuppression => {
    const waiting = s.state === "waiting";
    const own = s.created_by === me;
    const kind = s.agent_id ? "host" : s.group_id ? "group" : "all";
    return {
      id: s.id, rule_set_id: s.rule_set_id, rule_id: s.rule_id, what: s.what, exe: s.exe, args_sha256: s.args ? "demo" : null,
      where: { kind, agent_id: s.agent_id, hostname: data.agents.find((a) => a.id === s.agent_id)?.hostname ?? null, group_id: s.group_id, group_name: groupOf(s.group_id)?.name ?? null },
      for_days: s.for_days, status: expired(s) ? "expired" : s.state, reason: s.reason, requested_by: nameOf(s.created_by) ?? "",
      requested_at: s.created_at, decided_by: nameOf(s.decided_by), decided_at: s.decided_at, decision_reason: s.decision_reason,
      activated_at: s.activated_at, expires_at: s.expires_at, alarm_id: s.alarm_id,
      would_close: waiting ? wouldClose(s) : null, would_close_capped: false,
      can_decide: waiting && !own && inReach("alarms.suppressions.approve", s, false) && (!s.group_id || !!groupOf(s.group_id)),
      can_withdraw: waiting && own,
      can_remove: s.state === "active" && inReach("alarms.suppress", s, false),
    };
  };

  /** close_source: false positive, suppressed by `s`, if still open or investigating. */
  const closeSource = (s: Stored) => {
    const alarm = data.alarms.find((a) => a.id === s.alarm_id);
    if (!alarm || !["open", "investigating"].includes(alarm.state)) return;
    const note = `suppressed by #${s.id}`;
    alarm.state = "false_positive";
    alarm.suppressed_by = s.id;
    alarm.triage = { ...alarm.triage, state: "false_positive", note, version: alarm.triage.version + 1,
      updated_at: s.activated_at, updated_by: data.access.users.find((u) => u.user_id === (s.decided_by ?? s.created_by))?.username ?? actor };
  };
  // This persona's alarms were made fresh: close those active rows closed before.
  for (const s of rows) if (s.activated_at) closeSource(s);
  const activate = (s: Stored, at: string) => {
    s.state = "active";
    s.activated_at = at;
    s.expires_at = s.for_days === null ? null : new Date(Date.parse(at) + s.for_days * DAY).toISOString();
    closeSource(s);
  };
  const done = (s: Stored, action: string) => { save(); audit(action, s.id, "alarm_suppression"); return view(s); };

  return {
    view,
    /** list: waiting oldest first, then active (with expired) and rejected newest first, within the read reach. */
    list(state: string | null, alarmId: string | null) {
      const order: State[] = ["waiting", "active", "rejected"];
      return rows.filter((s) => order.includes(s.state) && (!state || s.state === state) && (!alarmId || s.alarm_id === alarmId)
          && inReach("alarms.suppressions.read", s, true))
        .sort((a, b) => order.indexOf(a.state) - order.indexOf(b.state)
          || (a.state === "waiting" ? a.created_at.localeCompare(b.created_at) : b.created_at.localeCompare(a.created_at)) || Number(b.id) - Number(a.id))
        .map(view);
    },
    options() {
      const sc = scope("alarms.suppress");
      const all = sc?.kind === "global";
      const groups = data.access.host_groups.filter((g) => all || (sc?.kind === "asset_groups" && sc.asset_group_ids.includes(g.asset_group_id)))
        .sort((a, b) => a.name.toLowerCase().localeCompare(b.name.toLowerCase()) || a.name.localeCompare(b.name))
        .map((g) => ({ id: g.asset_group_id, name: g.name }));
      return { require_approval: requireApproval(), all_hosts: all, groups };
    },
    request(req: Request): AlarmSuppression | Refusal {
      // A non-numeric alarm id is not found before anything is checked.
      if (!/^\d+$/.test(req.alarmId) || Number(req.alarmId) <= 0) return { status: 404, code: "alarm_not_found" };
      const reason = req.reason.trim();
      if (!validReason(reason)) return invalid("reason");
      if (req.forDays !== null && req.forDays !== 7 && req.forDays !== 30) return invalid("for");
      const sc = scope("alarms.suppress");
      const global = sc?.kind === "global";
      const where = req.where;
      if (where.kind === "group" && !global && !(sc?.kind === "asset_groups" && sc.asset_group_ids.includes(where.group_id))) return { status: 403, code: "permission_denied" };
      if (where.kind === "all" && !global) return { status: 403, code: "global_scope_required" };
      if (where.kind === "group" && !groupOf(where.group_id)) return invalid("group");
      const alarm = data.alarms.find((a) => a.id === req.alarmId && reaches("alarms.suppress", a.agent_id));
      if (!alarm) return { status: 404, code: "alarm_not_found" };
      const at = iso();
      const s: Stored = {
        id: String(rows.reduce((max, r) => Math.max(max, Number(r.id) || 0), 0) + 1), rule_set_id: alarm.rule_set_id, rule_id: alarm.rule_id,
        what: req.what, exe: alarm.exe, args: req.what === "command" ? alarm.process.args : null,
        agent_id: where.kind === "host" ? alarm.agent_id : null, group_id: where.kind === "group" ? where.group_id : null,
        for_days: req.forDays, state: "waiting", reason, created_by: me, created_at: at, decided_by: null, decided_at: null,
        decision_reason: null, activated_at: null, expires_at: null, alarm_id: alarm.id,
      };
      rows.push(s);
      if (requireApproval()) return done(s, "alarm.suppression.requested");
      activate(s, at);
      return done(s, "alarm.suppression.created");
    },
    decide(id: string, approve: boolean, why: string | null): AlarmSuppression | Refusal {
      const s = rows.find((r) => r.id === id && inReach("alarms.suppressions.approve", r, false));
      if (!s) return notFound;
      if (s.state !== "waiting") return { status: 409, code: "suppression_not_waiting" };
      if (s.created_by === me) return { status: 409, code: "own_request" };
      const reason = why?.trim() || null;
      if ((reason !== null && !validReason(reason)) || (!approve && reason === null)) return invalid("reason");
      if (approve && s.group_id && !groupOf(s.group_id)) return invalid("group");
      const at = iso();
      Object.assign(s, { decided_by: me, decided_at: at, decision_reason: reason });
      if (!approve) { s.state = "rejected"; return done(s, "alarm.suppression.rejected"); }
      activate(s, at);
      return done(s, "alarm.suppression.approved");
    },
    withdraw(id: string): AlarmSuppression | Refusal {
      const s = rows.find((r) => r.id === id && r.created_by === me);
      if (!s) return notFound;
      if (s.state !== "waiting") return { status: 409, code: "suppression_not_waiting" };
      Object.assign(s, { state: "withdrawn", decided_by: me, decided_at: iso() });
      return done(s, "alarm.suppression.withdrawn");
    },
    remove(id: string): AlarmSuppression | Refusal {
      const s = rows.find((r) => r.id === id && r.state === "active" && inReach("alarms.suppress", r, false));
      if (!s) return notFound;
      s.state = "removed";
      return done(s, "alarm.suppression.removed");
    },
    /** Waiting and active rows on a group, which deleting it ends. */
    onGroup: (groupId: string) => rows.filter((s) => s.group_id === groupId && (s.state === "waiting" || s.state === "active")).length,
    /** A group's delete: waiting rows are withdrawn, active ones removed; returns how many. */
    endGroup(groupId: string) {
      const ended = rows.filter((s) => s.group_id === groupId && (s.state === "waiting" || s.state === "active"));
      for (const s of ended) Object.assign(s, s.state === "waiting" ? { state: "withdrawn", decided_by: me, decided_at: iso() } : { state: "removed" });
      save();
      return ended.length;
    },
  };
}
export type Suppressions = ReturnType<typeof createSuppressions>;
