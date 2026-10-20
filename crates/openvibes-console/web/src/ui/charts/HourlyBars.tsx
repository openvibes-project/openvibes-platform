// 24 bars, oldest hour first, ending at the current hour. An SVG image
// with a <title> per bar (hover text) and a visually hidden table of the
// same values for screen readers.
const W = 240;
const H = 40;

/** Bar heights in pixels: the largest hour fills `max`; any non-zero hour shows at least 1. */
export function barHeights(values: number[], max: number): number[] {
  const top = Math.max(0, ...values);
  return values.map((v) => (v <= 0 || top === 0 ? 0 : Math.max(1, Math.round((v / top) * max))));
}

export function HourlyBars({ values, label }: Readonly<{ values: number[]; label: string }>) {
  const heights = barHeights(values, H);
  const step = W / Math.max(values.length, 1);
  const ago = (i: number) => (i === values.length - 1 ? "this hour" : `${values.length - 1 - i}h ago`);
  return (
    <figure className="hourly-bars">
      <svg viewBox={`0 0 ${W} ${H}`} role="img" aria-label={label} preserveAspectRatio="none" width="100%" height={H}>
        {values.map((v, i) => (
          <rect key={i} x={i * step + 1} width={step - 2} y={H - (heights[i] ?? 0)} height={heights[i] ?? 0} fill="var(--accent)">
            <title>{`${ago(i)}: ${v.toLocaleString()}`}</title>
          </rect>
        ))}
      </svg>
      <table className="sr-only">
        <caption>{label}</caption>
        <thead><tr><th scope="col">Hour</th><th scope="col">Count</th></tr></thead>
        <tbody>{values.map((v, i) => <tr key={i}><th scope="row">{ago(i)}</th><td>{v.toLocaleString()}</td></tr>)}</tbody>
      </table>
    </figure>
  );
}
