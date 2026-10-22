// The "Related" card of a detail page: labelled sections, each value a link
// when it has an href. No sections, no card. (The alarm page keeps its own.)
import type { ReactNode } from "react";

import { viewLink } from "../../app/nav";
import { Card } from "./DetailPage";

/** In-page view link like Tile's, or a plain string for an anchor or an external link. */
export type RelatedHref = string | { view: string; params?: Record<string, string> };

export function RelatedCard({ sections }: Readonly<{ sections: { label: string; value: ReactNode; href?: RelatedHref }[] }>) {
  if (sections.length === 0) return null;
  return (
    <Card title="Related">
      <div className="stack">
        {sections.map((s, i) => (
          <div key={`${i}:${s.label}`}>
            <h3 className="section-title">{s.label}</h3>
            {s.href ? <a className="object-link" {...(typeof s.href === "string" ? { href: s.href } : viewLink(s.href.view, s.href.params))}>{s.value}</a> : <div>{s.value}</div>}
          </div>
        ))}
      </div>
    </Card>
  );
}
