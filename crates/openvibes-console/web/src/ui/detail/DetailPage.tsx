// The shared layout of a detail page (approved screens 11 and 17): a
// header (icon, title, status, a facts line, actions), up to four tiles,
// then a narrow left and a wide right column of cards. A slot left empty
// draws nothing. `Card` is one card of either column.
import { Fragment, type ReactNode } from "react";

import { Icon } from "../Icon";

/** A card of the shared detail-page layout (approved screen 11); `flush` drops the body padding (a table); `id` is a tile's anchor. */
export const Card = ({ title, aside, flush, id, children }: { title: ReactNode; aside?: ReactNode; flush?: boolean; id?: string; children: ReactNode }) => (
  <section className="card person-card" id={id}>
    <div className="row row--between person-card__head"><h2 className="section-title">{title}</h2>{aside}</div>
    <div className={flush ? undefined : "person-card__body"}>{children}</div>
  </section>
);

const present = (node: ReactNode) => node !== null && node !== undefined && node !== false && node !== "";

export function DetailPage({ crumb, icon, title, status, facts = [], actions, error, tiles = [], left, right }: {
  crumb?: ReactNode;
  icon?: ReactNode;
  title: ReactNode;
  status?: ReactNode;
  /** Joined with " · "; empty ones are left out. */
  facts?: readonly ReactNode[];
  actions?: ReactNode;
  /** A refusal or failure of an action on the page. */
  error?: string | undefined;
  tiles?: readonly ReactNode[];
  left?: ReactNode;
  right?: ReactNode;
}) {
  const shownFacts = facts.filter(present);
  const shownTiles = tiles.filter(present);
  const cols = [left, right].filter(present);
  return (
    <div className="view person-page detail-page">
      {present(crumb) && <div className="view-pad person-page__crumb subtle">{crumb}</div>}
      <header className="person-page__head">
        {present(icon) && <span className="detail-page__icon" aria-hidden="true">{icon}</span>}
        <div className="stack grow person-page__title">
          <div className="row"><h1>{title}</h1>{status}</div>
          {shownFacts.length > 0 && (
            <span className="subtle detail-page__facts">
              {shownFacts.map((f, i) => <Fragment key={i}>{i > 0 && " · "}{f}</Fragment>)}
            </span>
          )}
        </div>
        {present(actions) && <div className="row person-page__actions">{actions}</div>}
      </header>
      {error && <div className="callout callout--bad person-page__error" role="alert"><Icon name="alert" size={16} /><span>{error}</span></div>}
      {shownTiles.length > 0 && <div className="detail-tiles">{shownTiles.map((t, i) => <Fragment key={i}>{t}</Fragment>)}</div>}
      {cols.length > 0 && (
        <div className={`person-page__cols${cols.length === 1 ? " detail-page__cols--one" : ""}`}>
          {present(left) && <div className="stack person-page__col">{left}</div>}
          {present(right) && <div className="stack person-page__col">{right}</div>}
        </div>
      )}
    </div>
  );
}
