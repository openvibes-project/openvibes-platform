// Alarm suppressions (approved screen 14) in the shared layout: By status and
// Recent changes on the left, one card per status on the right. Approvals
// live here: Approve and Reject… on waiting rows, Withdraw, Remove… and
// Ask again….
import { useState } from "react";

import { useResource } from "../../api/client";
import type { AlarmSuppression, AuditEvent } from "../../api/types";
import { useSession } from "../../app/session";
import { auditActionLabel } from "../../ui/auditActions";
import { ErrorBox, Loading } from "../../ui/bits";
import { ago } from "../../ui/format";
import { link } from "../admin/groups/groupApi";
import { Card } from "../admin/people/PersonPage";
import { SuppressionRow } from "./SuppressionRow";

const CARDS = [
  { key: "waiting", title: "Waiting", has: (s: AlarmSuppression) => s.status === "waiting", none: "No requests are waiting." },
  { key: "active", title: "Active", has: (s: AlarmSuppression) => s.status === "active" || s.status === "expired", none: "No suppression is active." },
  { key: "rejected", title: "Rejected", has: (s: AlarmSuppression) => s.status === "rejected", none: "Nothing rejected." },
] as const;
const anchor = (key: string) => `suppressions-${key}`;
const PREFIX = "alarm.suppression.";

/** `loading` and `failed` say so in the card instead of looking empty. */
type RecentLines = readonly AuditEvent[] | "loading" | "failed";

function Recent({ lines }: { lines: RecentLines }) {
  const none = lines === "loading" ? "Loading recent changes…" : lines === "failed" ? "Recent changes could not be loaded; the audit log has them." : "No suppression changes in the last 30 days.";
  return (
    <Card title="Recent changes" aside={<a {...link("/audit", { q: PREFIX })}>Audit log</a>}>
      {typeof lines === "string" || lines.length === 0 ? <p className="subtle person-page__none">{none}</p> : (
        <ul className="person-page__activity">
          {lines.map((e) => (
            <li key={e.id}>
              <span>{auditActionLabel(e.action)}{e.target_id ? ` #${e.target_id}` : ""}</span>
              <span className="subtle">{e.actor} · {ago(e.at)}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** The screen from the list; `recent` is undefined without audit access (the card is hidden). */
export function AlarmSuppressionsBody({ items, recent }: { items: readonly AlarmSuppression[]; recent?: RecentLines | undefined }) {
  // The row that moved to another card keeps focus there.
  const [focus, setFocus] = useState<string>();
  const done = (card: string) => (id: string, gone: boolean) => {
    if (gone) document.getElementById(anchor(card))?.focus();
    else setFocus(id);
  };
  return (
    <div className="view person-page">
      <header className="person-page__head">
        <div className="stack grow person-page__title"><h2>Alarm suppressions</h2><span className="subtle">Alarms that are closed as they arrive, and requests waiting for approval.</span></div>
      </header>
      <div className="person-page__cols">
        <div className="stack person-page__col">
          <Card title="By status">
            <ul className="person-page__activity">
              {CARDS.map((c) => (
                <li key={c.key}>
                  <a href={`#${anchor(c.key)}`} onClick={(e) => { e.preventDefault(); document.getElementById(anchor(c.key))?.scrollIntoView(); }}>{c.title}</a>
                  <span className="subtle num">{items.filter(c.has).length}</span>
                </li>
              ))}
            </ul>
          </Card>
          {recent && <Recent lines={recent} />}
        </div>
        <div className="stack person-page__col">
          {CARDS.map((c) => {
            const rows = items.filter(c.has);
            return (
              <div key={c.key} id={anchor(c.key)} tabIndex={-1} className="suppressions__card">
                <Card title={c.title}>
                  {rows.length === 0 ? <p className="subtle person-page__none">{c.none}</p> : (
                    <ul className="suppressions__rows">
                      {rows.map((s) => <SuppressionRow key={s.id} s={s} focus={focus === s.id} onDone={done(c.key)} />)}
                    </ul>
                  )}
                </Card>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

export function AlarmSuppressions() {
  const { can } = useSession();
  const [since] = useState(() => new Date(Date.now() - 30 * 86_400_000).toISOString());
  const list = useResource<{ items: AlarmSuppression[] }>("/api/v1/alarm-suppressions");
  const audit = useResource<{ items: AuditEvent[] }>(can("audit.read") ? `/api/v1/audit-events?since=${encodeURIComponent(since)}&action_prefix=${PREFIX}&limit=8` : null);
  if (list.error) return <div className="view-pad"><ErrorBox error={list.error} /></div>;
  if (!list.data) return <Loading />;
  const recent = !can("audit.read") ? undefined : audit.error ? "failed" : audit.data?.items ?? "loading";
  return <AlarmSuppressionsBody items={list.data.items} recent={recent} />;
}
