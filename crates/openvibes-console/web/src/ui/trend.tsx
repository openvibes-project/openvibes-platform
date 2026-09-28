// A small bar chart of how many hosts reported something each day.
export type DayCount = { day: string; hosts: number };

/** Distinct hosts per UTC day over the last `days` days, oldest first. */
export function dailyHosts(entries: readonly { agent_id: string; observed_day: string }[], days: number, now = Date.now()): DayCount[] {
  const byDay = new Map<string, Set<string>>();
  for (const entry of entries) {
    const hosts = byDay.get(entry.observed_day) ?? new Set<string>();
    hosts.add(entry.agent_id);
    byDay.set(entry.observed_day, hosts);
  }
  const today = new Date(now);
  return Array.from({ length: days }, (_, index) => {
    const day = new Date(Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - (days - 1 - index))).toISOString().slice(0, 10);
    return { day, hosts: byDay.get(day)?.size ?? 0 };
  });
}

export function Trend({ counts, label }: { counts: readonly DayCount[]; label: string }) {
  const max = Math.max(1, ...counts.map((c) => c.hosts));
  const first = counts[0];
  const last = counts[counts.length - 1];
  return (
    <figure className="trend">
      <div className="trend__bars" role="img" aria-label={`${label}: ${counts.map((c) => `${c.day} ${c.hosts}`).join(", ")}`}>
        {counts.map((c) => (
          <span key={c.day} className="trend__bar" style={{ height: `${Math.max(4, (c.hosts / max) * 100)}%` }} title={`${c.day}: ${c.hosts} hosts`} data-empty={c.hosts === 0 || undefined} />
        ))}
      </div>
      <figcaption className="row row--between subtle">
        <span>{first?.day}</span><span>{label}</span><span>{last?.day}</span>
      </figcaption>
    </figure>
  );
}
