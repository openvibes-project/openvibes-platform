// The group editor's state and words without React: a pure reducer over the
// draft, the bodies a save or preview sends, and the preview sentence.
import { ApiError, apiMessage } from "../../../api/client";
import type { CreateHostGroup, GroupCondition, HostGroup, HostGroupPreview, PreviewHostGroup, UpdateHostGroup } from "../../../api/types";

export type Picked = { agent_id: string; hostname: string };
export type Kind = "rule" | "manual";
export type Draft = {
  name: string; description: string; kind: Kind; conditions: Required<GroupCondition>[]; picked: Picked[];
  /** A stable React key per condition row, in step with `conditions`. */
  keys: number[];
};

/** The rule's fields, with the words for "holds" and "negated" (the server's group_words.rs). */
export const FIELDS = [
  { id: "os_family", label: "OS family", ops: ["is", "is not"] },
  { id: "distribution", label: "Distribution", ops: ["is", "is not"] },
  { id: "hostname", label: "Hostname", ops: ["matches", "does not match"] },
  { id: "ip", label: "IP address", ops: ["is in", "is not in"] },
] as const;
export const fieldDef = (id: string) => FIELDS.find((f) => f.id === id) ?? { id, label: id, ops: ["is", "is not"] as const };

const DISTROS: Record<string, string> = { debian: "Debian", ubuntu: "Ubuntu", fedora: "Fedora", rocky: "Rocky Linux", almalinux: "AlmaLinux" };

/** A value as people read it: "Windows", "Debian 12" (the server's host_group_facts names); unknown ids stay raw. */
export function valueLabel(field: string, value: string): string {
  if (field === "os_family") return { linux: "Linux", windows: "Windows" }[value] ?? value;
  if (field !== "distribution") return value;
  const [first = "", ...rest] = value.split(" ");
  return DISTROS[first] ? [DISTROS[first], ...rest].join(" ") : value;
}

export type Action =
  | { type: "name"; name: string }
  | { type: "description"; description: string }
  | { type: "kind"; kind: Kind }
  | { type: "add" }
  | { type: "remove"; index: number }
  | { type: "field"; index: number; field: string }
  | { type: "negate"; index: number; negate: boolean }
  | { type: "values"; index: number; values: string[] }
  | { type: "pick"; host: Picked }
  | { type: "unpick"; agent_id: string }
  | { type: "toRule" }
  | { type: "reset"; draft: Draft };

const condition = (): Required<GroupCondition> => ({ field: "os_family", negate: false, values: [] });

export const blankDraft = (kind: Kind): Draft => ({ name: "", description: "", kind, conditions: kind === "rule" ? [condition()] : [], picked: [], keys: kind === "rule" ? [0] : [] });
const nextKey = (d: Draft) => Math.max(-1, ...d.keys) + 1;

/** The draft of a saved group; an automatic group edits as a rule. */
export const fromGroup = (group: HostGroup, picked: Picked[]): Draft => ({
  name: group.name, description: group.description, kind: group.kind === "manual" ? "manual" : "rule",
  conditions: group.conditions.map((c) => ({ field: c.field, negate: c.negate ?? false, values: [...c.values] })), picked,
  keys: group.conditions.map((_, i) => i),
});

const edit = (d: Draft, index: number, change: Partial<GroupCondition>): Draft =>
  ({ ...d, conditions: d.conditions.map((c, i) => (i === index ? { ...c, ...change } : c)) });

export function reduce(d: Draft, a: Action): Draft {
  switch (a.type) {
    case "name": return { ...d, name: a.name };
    case "description": return { ...d, description: a.description };
    case "kind": return a.kind === "rule" && d.conditions.length === 0 ? { ...d, kind: a.kind, conditions: [condition()], keys: [nextKey(d)] } : { ...d, kind: a.kind };
    case "add": return { ...d, conditions: [...d.conditions, condition()], keys: [...d.keys, nextKey(d)] };
    case "remove": return { ...d, conditions: d.conditions.filter((_, i) => i !== a.index), keys: d.keys.filter((_, i) => i !== a.index) };
    // Another field's values mean nothing here ("windows" is no IP range).
    case "field": return edit(d, a.index, { field: a.field, values: [] });
    case "negate": return edit(d, a.index, { negate: a.negate });
    case "values": return edit(d, a.index, { values: a.values });
    case "pick": return d.picked.some((h) => h.agent_id === a.host.agent_id) ? d : { ...d, picked: [...d.picked, a.host] };
    case "unpick": return { ...d, picked: d.picked.filter((h) => h.agent_id !== a.agent_id) };
    case "toRule": return { ...d, kind: "rule", conditions: [condition()], keys: [nextKey(d)] };
    case "reset": return a.draft;
  }
}

const sameRule = (a: Draft, b: Draft) => JSON.stringify(a.conditions) === JSON.stringify(b.conditions);
const samePicks = (a: Draft, b: Draft) => a.picked.map((h) => h.agent_id).sort((x, y) => x.localeCompare(y)).join() === b.picked.map((h) => h.agent_id).sort((x, y) => x.localeCompare(y)).join();

/**
 * The user's edit (from `draft` against `oldBase`, what they started from)
 * moved onto `newBase`, a reload: what they changed stays, everything else
 * (someone else's rename, hosts they added) comes from the reload.
 */
export function rebase(draft: Draft, oldBase: Draft, newBase: Draft): Draft {
  const ruleTouched = draft.kind !== oldBase.kind || (draft.kind === "rule" && !sameRule(draft, oldBase));
  const had = new Set(oldBase.picked.map((h) => h.agent_id));
  const kept = new Set(draft.picked.map((h) => h.agent_id));
  const added = draft.picked.filter((h) => !had.has(h.agent_id) && !newBase.picked.some((n) => n.agent_id === h.agent_id));
  return {
    name: draft.name !== oldBase.name ? draft.name : newBase.name,
    description: draft.description !== oldBase.description ? draft.description : newBase.description,
    ...(ruleTouched ? { kind: draft.kind, conditions: draft.conditions, keys: draft.keys } : { kind: newBase.kind, conditions: newBase.conditions, keys: newBase.keys }),
    picked: [...newBase.picked.filter((h) => !had.has(h.agent_id) || kept.has(h.agent_id)), ...added],
  };
}

/** Whether the draft differs from what editing started from (worth asking before throwing it away). */
export const isDirty = (d: Draft, base: Draft) => Object.keys(patchBody(d, base, 0)).length > 1;

/** Whether saving would change who is in the group. */
export const membershipChanged = (d: Draft, base: Draft) => d.kind !== base.kind || (d.kind === "rule" ? !sameRule(d, base) : !samePicks(d, base));

const membership = (d: Draft) => (d.kind === "rule" ? { conditions: d.conditions } : { agent_ids: d.picked.map((h) => h.agent_id) });

/**
 * What Save sends: only the fields that changed, so a rename needs no say
 * over the hosts of every role reaching the group.
 */
export function patchBody(d: Draft, base: Draft, version: number): UpdateHostGroup {
  return {
    ...(d.name.trim() !== base.name ? { name: d.name.trim() } : {}),
    ...(d.description.trim() !== base.description ? { description: d.description.trim() } : {}),
    ...(membershipChanged(d, base) ? membership(d) : {}),
    version,
  };
}

export const createBody = (d: Draft): CreateHostGroup => ({ name: d.name.trim(), description: d.description.trim(), kind: d.kind, ...membership(d) });

/** The preview of a membership, once it is complete enough to ask about. */
export function previewBody(d: Draft): PreviewHostGroup | undefined {
  if (d.kind === "manual") return d.picked.length ? membership(d) : undefined;
  return d.conditions.length && d.conditions.every((c) => c.values.length) ? membership(d) : undefined;
}

const names = (shown: string[], total: number) => (total > shown.length ? `${shown.join(", ")} and ${total - shown.length} more` : shown.join(", "));
const host = (h: { agent_id: string; hostname?: string | null }) => h.hostname || h.agent_id;

/** The preview as parts: the "+N"/"−M" changes with their hosts, then who gains or loses access. */
export function previewParts(p: HostGroupPreview, verb: "save" | "delete" = "save") {
  const changes = [
    ...(p.joins_total ? [{ sign: `+${p.joins_total}`, hosts: names(p.joins.map(host), p.joins_total) }] : []),
    ...(p.leaves_total ? [{ sign: `−${p.leaves_total}`, hosts: names(p.leaves.map(host), p.leaves_total) }] : []),
  ];
  const people = [...new Set([...p.gains, ...p.loses].map((x) => x.display_name))];
  const total = Math.max(p.people_total, people.length);
  // "Wendy Ward gains", "Wendy Ward, Tom Tanaka gain" (approved copy is the plural).
  const s = total === 1 ? "s" : "";
  const how = p.gains.length && p.loses.length ? `gain${s} and lose${s} access accordingly` : p.gains.length ? `gain${s} access to them` : `lose${s} access to them`;
  return { lead: `If you ${verb}: `, changes, people: people.length ? ` ${names(people, total)} ${how}.` : "" };
}

/** "If you save: +2 (web-01, db-02). Wendy Ward gain access to them."; empty when nothing changes. */
export function previewSentence(p: HostGroupPreview, verb: "save" | "delete" = "save"): string {
  const { lead, changes, people } = previewParts(p, verb);
  return changes.length ? `${lead}${changes.map((c) => `${c.sign} (${c.hosts})`).join(", ")}.${people}` : "";
}

export const STALE = "Someone else changed this group. It has been reloaded.";

/** What to say when a save or delete is refused, and whether to reload the group. */
export function refusal(error: unknown, fallback: string): { message: string; reload: boolean } {
  if (error instanceof ApiError && error.code === "stale_group") return { message: STALE, reload: true };
  if (error instanceof ApiError && error.code === "group_in_use") {
    const roles = Array.isArray(error.body?.roles) ? (error.body.roles as string[]).join(", ") : "";
    return { message: `${error.message}: ${roles || "reload to see which"}.`, reload: true };
  }
  const field = error instanceof ApiError ? error.fieldErrors?.[0]?.message : undefined;
  return { message: field ?? apiMessage(error, fallback), reload: false };
}

/** "4 hosts"; for someone who does not see every host the count is about them, not the group: "2 hosts you can see". */
export const hostsLabel = (n: number, seesAll: boolean) =>
  (seesAll ? `${n} ${n === 1 ? "host" : "hosts"}` : n === 0 ? "No hosts you can see" : `${n} ${n === 1 ? "host" : "hosts"} you can see`);

/** The membership sentence; a manual group's count is left out for someone who does not see every host. */
export const membershipText = (g: HostGroup, seesAll: boolean) => (g.kind === "manual" && !seesAll ? "Hosts picked by hand" : g.membership);
