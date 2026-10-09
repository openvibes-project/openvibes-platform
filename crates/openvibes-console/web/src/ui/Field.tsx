import type { ReactNode } from "react";

/** A labelled Select. Never a <label> around a Select (invalid HTML; the popup's clicks would re-click the button): the Select carries its own aria-label. */
export function SelectField({ label, children }: { label: string; children: ReactNode }) {
  return <div className="field"><span>{label}</span>{children}</div>;
}
