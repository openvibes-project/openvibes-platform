// A tile of a detail page that is a fact, not a count to follow: "First
// seen", "Confidence". Same look as Tile, no link.
import type { ReactNode } from "react";

export function FactTile({ label, value }: Readonly<{ label: string; value: ReactNode }>) {
  return (
    <div className="card detail-tile">
      <span className="detail-tile__value num">{value}</span>
      <span className="detail-tile__label subtle">{label}</span>
    </div>
  );
}
