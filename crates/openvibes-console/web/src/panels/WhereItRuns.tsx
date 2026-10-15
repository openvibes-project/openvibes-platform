// Settings › Rule sets › a set's panel: "Where it runs" (approved screens 2–5,
// docs/specs/rule-set-assignment-ui/approved.md): the default switch, the
// groups that override it, and the inline row that adds one. The switches show
// the server's state: a failed change leaves them as they were.
import { useRef, useState } from "react";
import type { KeyboardEvent } from "react";

import { ApiError, invalidate, request } from "../api/client";
import type { AssignableGroup, RuleSetAssignment } from "../api/types";
import { Icon } from "../ui/Icon";
import { Section } from "../ui/panel";
import { Segmented } from "../ui/Segmented";
import { Select } from "../ui/Select";
import { Switch } from "../ui/Switch";
import { toast } from "../ui/toast";
import { addGroupBlocked, shortName } from "./ruleAssignment";

const EXPLAIN = "A host runs it when any of its groups has it on; otherwise when the default is on. Hosts follow on their next scan. Switching it off ends that host's findings from this set (their triage stays).";
const NOTE_BOX = { display: "block", border: "1px solid var(--line-strong)", borderRadius: 8, padding: "10px 12px" } as const;

const Tags = ({ selectors }: { selectors: readonly string[] }) => (
  <span className="row row--wrap">{selectors.map((s) => <span key={s} className="tag">{s}</span>)}</span>
);

export function WhereItRuns({ assignment, groups, canChange }: { assignment: RuleSetAssignment; groups: readonly AssignableGroup[]; canChange: boolean }) {
  const id = assignment.rule_set_id;
  const base = `/api/v1/rule-set-assignments/${encodeURIComponent(id)}`;
  const [busy, setBusy] = useState(false);
  const [adding, setAdding] = useState<{ group: string; on: boolean } | null>(null);
  const addButton = useRef<HTMLButtonElement>(null);
  const addRow = useRef<HTMLTableRowElement>(null);
  const byId = new Map(groups.map((g) => [g.asset_group_id, g]));
  const free = groups.filter((g) => !assignment.groups.some((o) => o.asset_group_id === g.asset_group_id));
  const blocked = addGroupBlocked(groups.length, free.length);

  const change = (method: "PUT" | "DELETE", path: string, body: unknown, done: string) => {
    setBusy(true);
    request(method, path, body)
      .then(() => toast(done), (error: unknown) => toast(
        !(error instanceof ApiError) ? "The change failed" : error.code === "asset_group_not_found" ? "Asset group not found" : error.message, true))
      .finally(() => { setBusy(false); invalidate("/api/v1/rule-set-assignments"); invalidate("/api/v1/agents/"); });
  };
  const setGroup = (groupId: string, name: string, on: boolean) =>
    change("PUT", `${base}/groups/${encodeURIComponent(groupId)}`, { enabled: on }, `${id} is now ${on ? "on" : "off"} for ${name}`);
  const open = () => {
    const first = free[0];
    if (!first) return;
    setAdding({ group: first.asset_group_id, on: !assignment.default_enabled });
    requestAnimationFrame(() => addRow.current?.querySelector<HTMLElement>('[role="combobox"]')?.focus());
  };
  const cancel = () => { setAdding(null); requestAnimationFrame(() => addButton.current?.focus()); };
  const add = () => {
    if (!adding) return;
    setGroup(adding.group, byId.get(adding.group)?.name ?? adding.group, adding.on);
    setAdding(null);
  };
  // Esc cancels the add row, and does not close the panel.
  const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") { event.stopPropagation(); cancel(); } };
  const chosen = adding ? byId.get(adding.group) : undefined;

  return (
    <Section title="Where it runs">
      <div className="stack" onKeyDown={adding ? onKey : undefined}>
        {!assignment.published && (
          <div style={NOTE_BOX}><b>Not available yet.</b> <span className="subtle">{`This platform has no ${shortName(id)} set yet: it comes with a later rules package. Switches you set now are kept and apply when it is published.`}</span></div>
        )}
        <Switch label="On for Linux hosts by default" checked={assignment.default_enabled} disabled={!canChange || busy}
          onChange={(on) => change("PUT", base, { default_enabled: on }, `${id} is now ${on ? "on" : "off"} by default`)} />
        {assignment.published && <p className="subtle">Runs on <b>{assignment.hosts_on}</b> Linux hosts · off on <b>{assignment.hosts_off}</b>.</p>}
        {assignment.groups.length === 0 && !adding ? <p className="subtle">No group differs from the default.</p> : (
          <table className="table table--compact" aria-label="Group overrides">
            <thead><tr><th>Group</th><th>Matches</th><th className="num">Hosts</th><th className="num">Runs</th></tr></thead>
            <tbody>
              {assignment.groups.map((o) => (
                <tr key={o.asset_group_id}>
                  <td><div className="truncate" style={{ maxWidth: 220 }} title={o.name}>{o.name}</div></td>
                  <td><Tags selectors={byId.get(o.asset_group_id)?.selectors ?? []} /></td>
                  <td className="num subtle">{byId.get(o.asset_group_id)?.hosts ?? "—"}</td>
                  <td className="num">
                    <span className="row" style={{ justifyContent: "flex-end", gap: 6 }}>
                      <Switch bare label={`Runs for ${o.name}`} checked={o.enabled} disabled={!canChange || busy} onChange={(on) => setGroup(o.asset_group_id, o.name, on)} />
                      {canChange && (
                        <button type="button" className="icon-button" aria-label={`Remove ${o.name}`} title={`Remove: ${o.name} follows the default again`} disabled={busy}
                          onClick={() => change("DELETE", `${base}/groups/${encodeURIComponent(o.asset_group_id)}`, undefined, `${o.name} follows the default again`)}>
                          <Icon name="close" size={14} />
                        </button>
                      )}
                    </span>
                  </td>
                </tr>
              ))}
              {adding && (
                <tr ref={addRow}>
                  <td><Select small label="Group" value={adding.group} onChange={(group) => setAdding({ ...adding, group })} options={free.map((g) => ({ value: g.asset_group_id, label: g.name }))} /></td>
                  <td><Tags selectors={chosen?.selectors ?? []} /></td>
                  <td className="num subtle">{chosen?.hosts ?? 0}</td>
                  <td className="num">
                    <Segmented label="Runs" value={adding.on ? "on" : "off"} onChange={(v) => setAdding({ ...adding, on: v === "on" })}
                      options={[{ value: "on", label: "On" }, { value: "off", label: "Off" }]} />
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        )}
        {canChange && (
          <div className="row">
            {adding ? (
              <>
                <button type="button" className="button button--small button--primary" disabled={busy} onClick={add}>Add</button>
                <button type="button" className="button button--small" onClick={cancel}>Cancel</button>
              </>
            ) : (
              <>
                <button ref={addButton} type="button" className="button button--small" disabled={blocked !== null || busy} onClick={open}>+ Add group</button>
                {blocked && <span className="subtle">{blocked}</span>}
              </>
            )}
          </div>
        )}
        <p className="subtle">{EXPLAIN}</p>
      </div>
    </Section>
  );
}
