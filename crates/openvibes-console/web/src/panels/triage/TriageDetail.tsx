// The triage history of one item (an alarm's page, approved screen 30):
// who changed its state, when, from and to, and the note. The detail
// template, its Hosts tab and the finding panel that used them are gone:
// alarms, checks and vulnerabilities are pages now (screens 30, 28 and 26).
import { useResource } from "../../api/client";
import { Ago, Empty, ErrorBox, Loading, TriageBadge } from "../../ui/bits";

type Event = { agent_id: string; hostname?: string | null; from_state?: string | null; to_state: string; note?: string | null; changed_at: string; changed_by: string };

/** The triage changes, newest first: who, when, from and to, the note. */
export function HistoryTab({ query, showHost }: Readonly<{ query: string; showHost: boolean }>) {
  const history = useResource<{ items: Event[] }>(`/api/v1/triage-history?${query}`);
  if (history.error) return <div className="panel-body"><ErrorBox error={history.error} /></div>;
  if (!history.data) return <Loading rows={3} />;
  if (history.data.items.length === 0) return <Empty title="No triage changes yet" />;
  return (
    <ol className="list list--plain detail-history">
      {history.data.items.map((e, index) => (
        <li key={`${e.changed_at}-${index}`} className="list__row list__row--static">
          <div className="stack">
            <span>
              {e.from_state ? <><TriageBadge state={e.from_state} /> → </> : null}<TriageBadge state={e.to_state} />
              {showHost && <span className="subtle"> on {e.hostname ?? e.agent_id}</span>}
            </span>
            {e.note && <span>{e.note}</span>}
            <span className="subtle">{e.changed_by} · <Ago value={e.changed_at} /></span>
          </div>
        </li>
      ))}
    </ol>
  );
}
