import { useLayoutEffect, useRef, useState } from "react";

import { axisDays, clampIndex, dayLabel, emptyNote, indexAt, spansYears, layout, monotonePath, niceMax, segments, spreadLabels, steppedPath, tableRows, ticks, tipLeft, xAt, yAt, ariaLabel, type Series } from "./linechart";

export type { Series };

type Props = { series: Series[]; variant: "spark" | "full"; smooth: boolean };

/** Line chart drawn at pixel size (no stretched viewBox); see linechart.ts for the geometry. */
export function LineChart({ series, variant, smooth }: Props) {
  const box = useRef<HTMLDivElement>(null);
  const tip = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(0);
  const [hoverRaw, setHover] = useState<number | null>(null);
  const [table, setTable] = useState(false);

  const note = emptyNote(series);
  const empty = note !== null;
  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    setWidth(el.clientWidth);
    const observer = new ResizeObserver(([entry]) => setWidth(entry?.contentRect.width ?? el.clientWidth));
    observer.observe(el);
    return () => observer.disconnect();
  }, [table, empty]);

  const days = axisDays(series);
  const n = days.length;
  const hover = clampIndex(hoverRaw, n);
  const year = spansYears(days);
  const today = new Date().toISOString().slice(0, 10);
  const full = variant === "full";
  const multi = series.length > 1;
  const l = layout(variant, width, multi);
  const max = niceMax(Math.max(0, ...series.flatMap((s) => s.points.map((p) => p.value))));
  const index = new Map(days.map((d, i) => [d, i]));
  const dots = (s: Series) => s.points.map((p) => ({ x: xAt(index.get(p.day) ?? 0, n, l), y: yAt(p.value, max, l), day: p.day }));
  const build = smooth ? monotonePath : steppedPath;
  const lastY = series.map((s) => yAt(s.points.at(-1)?.value ?? 0, max, l));
  const endY = multi ? spreadLabels(lastY, 11) : lastY;

  useLayoutEffect(() => {
    const t = tip.current;
    const b = box.current;
    if (hover === null || !t || !b) return;
    t.style.left = `${tipLeft(xAt(hover, n, layout(variant, b.clientWidth, multi)), t.offsetWidth, b.clientWidth)}px`;
  }, [hover, n, variant, multi]);

  const label = ariaLabel(series);
  if (note !== null) return <div className="linechart linechart--empty subtle" ref={box}>{note}</div>;
  if (table) {
    return (
      <div className="linechart" ref={box}>
        <div className="linechart__table">
          <table>
            <thead><tr><th scope="col">Day</th>{series.map((s) => <th key={s.label} scope="col">{s.label}</th>)}</tr></thead>
            <tbody>{tableRows(series).map(([day, ...values]) => <tr key={day}><th scope="row">{day}</th>{values.map((v, i) => <td key={i} className="num">{v}</td>)}</tr>)}</tbody>
          </table>
        </div>
        <button type="button" className="linechart__toggle" onClick={() => setTable(false)}>Show as chart</button>
      </div>
    );
  }

  const xLabels = full ? [...new Set([0, Math.floor((n - 1) / 2), n - 1])] : [];
  const hoverDay = hover === null ? undefined : days[hover];
  return (
    <div className="linechart" ref={box} data-variant={variant}>
      {width > 0 && (
        <svg width={width} height={l.H} viewBox={`0 0 ${width} ${l.H}`} role="img" aria-label={label}>
          {full ? ticks(max).map((t) => (
            <g key={t}>
              <line className="linechart__grid" x1={l.padL} x2={width - l.padR} y1={yAt(t, max, l)} y2={yAt(t, max, l)} />
              <text className="linechart__ax" x={l.padL - 6} y={yAt(t, max, l) + 3} textAnchor="end">{t}</text>
            </g>
          )) : <line className="linechart__grid" x1={l.padL} x2={width - l.padR} y1={yAt(0, max, l) + 0.5} y2={yAt(0, max, l) + 0.5} />}
          {xLabels.map((i) => (
            <text key={i} className="linechart__ax" x={xAt(i, n, l)} y={l.H - 5} textAnchor={i === 0 && n > 1 ? "start" : i === n - 1 ? "end" : "middle"}>{dayLabel(days[i] ?? "", today, year && i === 0)}</text>
          ))}
          {series.map((s, si) => (
            <g key={s.label} data-s={si}>
              {segments(s.points).map((run) => {
                const pts = run.map((p) => ({ x: xAt(index.get(p.day) ?? 0, n, l), y: yAt(p.value, max, l) }));
                const a = pts[0];
                const z = pts[pts.length - 1];
                if (!a || !z) return null;
                const d = build(pts);
                return (
                  <g key={run[0]?.day}>
                    {!multi && pts.length > 1 && <path className="linechart__area" d={`${d}H${z.x}V${yAt(0, max, l)}H${a.x}Z`} />}
                    {pts.length > 1 ? <path className="linechart__line" d={d} /> : <circle className="linechart__line-dot" cx={a.x} cy={a.y} r={2} />}
                  </g>
                );
              })}
              {(() => {
                const last = dots(s).at(-1);
                return last && <circle className="linechart__dot" cx={last.x} cy={last.y} r={full ? 4 : 3} />;
              })()}
              {multi && <text className="linechart__end" x={width - l.padR + 6} y={(endY[si] ?? 0) + 3}>{s.points.at(-1)?.value}</text>}
            </g>
          ))}
          {hover !== null && (
            <g pointerEvents="none">
              <line className="linechart__cross" x1={xAt(hover, n, l)} x2={xAt(hover, n, l)} y1={l.padT} y2={l.H - l.padB} />
              {series.map((s, si) => {
                const p = s.points.find((q) => q.day === hoverDay);
                return p && <circle key={s.label} data-s={si} className="linechart__dot" cx={xAt(hover, n, l)} cy={yAt(p.value, max, l)} r={4} />;
              })}
            </g>
          )}
          <rect width={width} height={l.H} fill="transparent"
            onPointerMove={(e) => setHover(indexAt(e.clientX - e.currentTarget.getBoundingClientRect().left, n, l))}
            onPointerLeave={() => setHover(null)} />
        </svg>
      )}
      {hover !== null && hoverDay && (
        <div className="linechart__tip" ref={tip}>
          {dayLabel(hoverDay, today, year)}{!multi && " · "}
          {series.map((s, si) => {
            const v = s.points.find((p) => p.day === hoverDay)?.value ?? "–";
            return multi
              ? <span key={s.label} className="linechart__tip-row" data-s={si}><i className="linechart__swatch" />{s.label} <b>{v}</b></span>
              : <b key={s.label}>{v}</b>;
          })}
        </div>
      )}
      {multi && <ul className="linechart__legend">{series.map((s, si) => <li key={s.label} data-s={si}><i className="linechart__swatch" />{s.label}</li>)}</ul>}
      {full && <button type="button" className="linechart__toggle" onClick={() => setTable(true)}>Show as table</button>}
    </div>
  );
}
