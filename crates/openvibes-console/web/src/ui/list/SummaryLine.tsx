// A list's summary line: "9 online · 4 with an older agent". A live region
// that stays in the page, so a change of filters is announced.

export type SummaryPart = { count: number; text: string };

/** `skipZero` leaves out parts that count nothing. */
export function SummaryLine({ parts, skipZero }: { parts: readonly SummaryPart[]; skipZero?: boolean }) {
  const shown = skipZero ? parts.filter((p) => p.count !== 0) : parts;
  return (
    <p className="summary-line subtle" role="status">
      {shown.map((p) => `${p.count.toLocaleString()} ${p.text}`).join(" · ")}
    </p>
  );
}
