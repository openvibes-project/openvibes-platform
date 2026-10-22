// The "Related" card of a detail page: labelled sections, each value a link
// when it has an href. No sections, no card. (The alarm page keeps its own.)
import type { ReactNode } from "react";

import { Card } from "./DetailPage";

export function RelatedCard({ sections }: Readonly<{ sections: { label: string; value: ReactNode; href?: string }[] }>) {
  if (sections.length === 0) return null;
  return (
    <Card title="Related">
      <div className="stack">
        {sections.map((s) => (
          <div key={s.label}>
            <h3 className="section-title">{s.label}</h3>
            {s.href ? <a className="object-link" href={s.href}>{s.value}</a> : <div>{s.value}</div>}
          </div>
        ))}
      </div>
    </Card>
  );
}
