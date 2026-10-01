// "Show more" for a panel's host list (board #104): the first page comes
// with the panel's own load; further pages are appended on request, from
// the same path with the page's cursor. A reload of the first page starts
// over, so a refreshed list never shows stale extra rows.
import { useState } from "react";

import { request } from "../api/client";

type Page<H> = { hosts: H[]; next_cursor?: string | null };

export function useMoreHosts<H>(path: string, first: Page<H> | undefined) {
  const [extra, setExtra] = useState<{ from: Page<H> | undefined; hosts: H[]; cursor: string | null }>({ from: undefined, hosts: [], cursor: null });
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);
  const fresh = first !== undefined && extra.from === first;
  const hosts = [...(first?.hosts ?? []), ...(fresh ? extra.hosts : [])];
  const cursor = fresh ? extra.cursor : first?.next_cursor ?? null;
  const more = async () => {
    if (!cursor || busy) return;
    setBusy(true);
    setFailed(false);
    try {
      const page = await request<Page<H>>("GET", `${path}${path.includes("?") ? "&" : "?"}cursor=${encodeURIComponent(cursor)}`);
      setExtra({ from: first, hosts: [...(fresh ? extra.hosts : []), ...page.hosts], cursor: page.next_cursor ?? null });
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  };
  return { hosts, more: cursor ? more : undefined, busy, failed };
}

/** The button under a host list while more pages exist. */
export function ShowMore({ shown, more, busy, failed }: { shown: number; more: (() => void) | undefined; busy: boolean; failed: boolean }) {
  if (!more) return null;
  return (
    <div className="view-pad stack">
      <p className="subtle" role="status">Showing {shown} hosts.{failed ? " The next page could not be loaded." : ""}</p>
      <div><button type="button" className="button" onClick={more} disabled={busy}>{busy ? "Loading…" : failed ? "Try again" : "Show more hosts"}</button></div>
    </div>
  );
}
