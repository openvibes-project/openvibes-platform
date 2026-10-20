// One tile of a detail page: a number and what it counts, leading to the
// full list it comes from (approved screen 17).
import { viewLink } from "../../app/nav";

export type TileLink = { view: string; params?: Record<string, string> };

export function Tile({ label, value, to }: { label: string; value: number; to: TileLink }) {
  const shown = value.toLocaleString();
  return (
    <a className="card detail-tile" {...viewLink(to.view, to.params)} aria-label={`${label}: ${shown}`}>
      <span className="detail-tile__value num">{shown}</span>
      <span className="detail-tile__label subtle">{label}</span>
    </a>
  );
}
