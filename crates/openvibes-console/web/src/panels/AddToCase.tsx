// "Add to case": a button on an alarm, finding, vulnerability, host or
// software that adds it to an open case, or to a new one. An alarm, finding
// or vulnerability can be in one open case only, so when it is in one the
// menu says which and links to it instead of offering more.
import { type CSSProperties, type FormEvent, type RefObject, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { invalidate, request, useAllPages, useResource } from "../api/client";
import type { CaseDetail, CaseSummary, ItemCases } from "../api/types";
import { useSession } from "../app/session";
import { CaseStatusBadge } from "../views/Cases";
import { ErrorBox, Loading, ObjectLink } from "../ui/bits";
import { Icon } from "../ui/Icon";
import { toast } from "../ui/toast";
import { type CaseKind, EXCLUSIVE_KINDS, caseErrorText, caseNumber, kindLabel } from "./cases";

type Where = { top?: number; bottom?: number; left: number; width: number; maxHeight: number };

/** Where to put the menu: under the button, or over it when there is more room above. */
function place(rect: DOMRect): Where {
  const width = Math.min(340, window.innerWidth - 16);
  const left = Math.max(8, Math.min(rect.right - width, window.innerWidth - width - 8));
  const below = window.innerHeight - rect.bottom - 14;
  return below >= 300 || below >= rect.top
    ? { top: rect.bottom + 6, left, width, maxHeight: Math.max(160, below) }
    : { bottom: window.innerHeight - rect.top + 6, left, width, maxHeight: Math.max(160, rect.top - 14) };
}

/** `inCase`: the number of the open case already holding it; the button names it. */
export function AddToCase({ kind, id, label, compact, inCase }: { kind: CaseKind; id: string; label: string; compact?: boolean; inCase?: number | undefined }) {
  const { can } = useSession();
  const [where, setWhere] = useState<Where | null>(null);
  const button = useRef<HTMLButtonElement>(null);
  const close = useCallback(() => setWhere(null), []);
  if (!can("cases.manage")) return null;
  return (
    <>
      <button ref={button} type="button" className={compact ? "button button--small button--ghost button--icon" : "button"} aria-haspopup="dialog" aria-expanded={where !== null}
        aria-label={compact ? `Add ${label} to a case` : undefined} title={compact ? "Add to case" : undefined}
        onClick={(event) => setWhere(where === null ? place(event.currentTarget.getBoundingClientRect()) : null)}>
        <Icon name="cases" size={compact ? 14 : 15} />{compact ? <Icon name="plus" size={12} /> : inCase !== undefined ? caseNumber(inCase) : "Add to case"}
      </button>
      {where !== null && createPortal(
        <Menu kind={kind} id={id} label={label} where={where} anchor={button} onClose={close} />, document.body)}
    </>
  );
}

function Menu({ kind, id, label, where, anchor, onClose }: { kind: CaseKind; id: string; label: string; where: Where; anchor: RefObject<HTMLButtonElement | null>; onClose: () => void }) {
  const dialog = useRef<HTMLDivElement>(null);
  const holders = useResource<ItemCases>(`/api/v1/cases/for-item?kind=${kind}&ref=${encodeURIComponent(id)}`);
  const open = useAllPages<CaseSummary>("/api/v1/cases");
  const [creating, setCreating] = useState(false);
  const [title, setTitle] = useState(label.slice(0, 120));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  useEffect(() => {
    const dismiss = (restore: boolean) => { onClose(); if (restore) anchor.current?.focus(); };
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") { event.stopPropagation(); dismiss(true); } };
    const onPointer = (event: PointerEvent) => {
      const target = event.target as Node;
      if (!dialog.current?.contains(target) && !anchor.current?.contains(target)) dismiss(false);
    };
    const onScroll = (event: Event) => { if (!dialog.current?.contains(event.target as Node)) dismiss(false); };
    document.addEventListener("keydown", onKey, true);
    document.addEventListener("pointerdown", onPointer);
    window.addEventListener("scroll", onScroll, true);
    window.addEventListener("resize", onClose);
    return () => {
      document.removeEventListener("keydown", onKey, true);
      document.removeEventListener("pointerdown", onPointer);
      window.removeEventListener("scroll", onScroll, true);
      window.removeEventListener("resize", onClose);
    };
  }, [anchor, onClose]);

  useEffect(() => { dialog.current?.focus(); }, []);

  const exclusive = EXCLUSIVE_KINDS.has(kind);
  const holding = holders.data?.items ?? [];
  const held = new Set(holding.map((entry) => entry.case.case_id));
  const choices = (open.data ?? []).filter((c) => !held.has(c.case_id));
  const taken = exclusive ? holding[0]?.case : undefined;
  const style: CSSProperties = { ...(where.top !== undefined ? { top: where.top } : { bottom: where.bottom }), left: where.left, width: where.width, maxHeight: where.maxHeight };

  /** Runs the change; its result is what to tell the user. A refusal may mean the lists are out of date, so they reload. */
  const run = (change: () => Promise<string>) => {
    setBusy(true);
    setError(undefined);
    change().then((done) => { invalidate("/api/v1/case"); toast(done); }, (e: unknown) => { setError(caseErrorText(e)); invalidate("/api/v1/case"); }).finally(() => setBusy(false));
  };
  const addTo = (c: CaseSummary) => run(async () => {
    await request("POST", `/api/v1/cases/${encodeURIComponent(c.case_id)}/items`, { kind, ref: id });
    return `Added to ${caseNumber(c.number)}`;
  });
  const create = (event: FormEvent) => {
    event.preventDefault();
    if (busy || title.trim() === "") return;
    run(async () => {
      const made = await request<CaseDetail>("POST", "/api/v1/cases", { title: title.trim(), items: [{ kind, ref: id }] });
      setCreating(false);
      return `Opened ${caseNumber(made.number)} with this item`;
    });
  };

  return (
    <div ref={dialog} className="popover" role="dialog" aria-label={`Add ${kindLabel[kind].toLowerCase()} to a case`} tabIndex={-1} style={style}
      onClickCapture={(event) => { if ((event.target as HTMLElement).closest("a")) onClose(); }}>
      <p className="popover__title"><strong>Add to case</strong> <span className="subtle truncate">{label}</span></p>
      {holders.error ? <ErrorBox error={holders.error} /> : holders.loading && !holders.data ? <Loading rows={2} /> : (
        <>
          {holding.length > 0 && (
            <div className="popover__section">
              <p className="subtle">{exclusive ? "Already in an open case; an item is in one at a time:" : "Also in:"}</p>
              <ul className="pick pick--static">
                {holding.map(({ case: c }) => (
                  <li key={c.case_id}>
                    <ObjectLink to={{ kind: "case", id: c.case_id }} className="pick__row">
                      <span className="mono">{caseNumber(c.number)}</span><span className="grow truncate">{c.title}</span><CaseStatusBadge status={c.status} resolution={c.resolution} />
                    </ObjectLink>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {!taken && !creating && (
            <div className="popover__section">
              <p className="subtle" aria-hidden="true">{holding.length > 0 ? "Or add it to another open case:" : "Add it to an open case:"}</p>
              {open.error ? <ErrorBox error={open.error} /> : open.loading && !open.data ? <Loading rows={2} /> : choices.length === 0 ? <p className="subtle">No other open case.</p> : (
                <ul className="pick" aria-label="Add to an open case">
                  {choices.map((c) => (
                    <li key={c.case_id}>
                      <button type="button" className="pick__row" disabled={busy} onClick={() => addTo(c)}>
                        <span className="mono">{caseNumber(c.number)}</span><span className="grow truncate">{c.title}</span><CaseStatusBadge status={c.status} />
                      </button>
                    </li>
                  ))}
                </ul>
              )}
              <button type="button" className="button button--small" onClick={() => setCreating(true)}><Icon name="plus" size={14} /> New case…</button>
            </div>
          )}
          {!taken && creating && (
            <form className="popover__section stack" onSubmit={create}>
              <label className="field">Title<input className="input" required autoFocus maxLength={120} value={title} onChange={(event) => setTitle(event.target.value)} /></label>
              <p className="subtle">Its severity starts from this item.</p>
              <div className="row">
                <button type="submit" className="button button--small button--primary" disabled={busy || title.trim() === ""}>{busy ? "Opening…" : "Open case"}</button>
                <button type="button" className="button button--small button--ghost" onClick={() => setCreating(false)}>Back</button>
              </div>
            </form>
          )}
        </>
      )}
      {error && <p className="confirm__error" role="alert">{error}</p>}
    </div>
  );
}
