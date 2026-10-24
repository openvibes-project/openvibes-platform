// A list's summary line: "9 online · 4 with an older agent". A live region
// that stays in the page, so a change of filters is announced.

export type SummaryPart = { count: number; text: string };

/** `skipZero` leaves out parts that count nothing; `tail` ends the line (such as "baseline 6, hardening 4"). */
export function SummaryLine({ parts, skipZero, tail }: { parts: readonly SummaryPart[]; skipZero?: boolean; tail?: string }) {
  const shown = skipZero ? parts.filter((p) => p.count !== 0) : parts;
  return (
    <p className="summary-line subtle" role="status">
      {[...shown.map((p) => `${p.count.toLocaleString()} ${p.text}`), ...(tail ? [tail] : [])].join(" · ")}
    </p>
  );
}
