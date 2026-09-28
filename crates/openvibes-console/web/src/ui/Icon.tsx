// A small stroke icon set (24px grid, drawn in the style of Lucide, MIT),
// inline so the console needs no icon dependency.
const c = (x: number, y: number, r: number) => `M${x - r} ${y}a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0`;
const rr = (x: number, y: number, w: number, h: number, r: number) =>
  `M${x + r} ${y}h${w - 2 * r}a${r} ${r} 0 0 1 ${r} ${r}v${h - 2 * r}a${r} ${r} 0 0 1 ${-r} ${r}h${-(w - 2 * r)}a${r} ${r} 0 0 1 ${-r} ${-r}v${-(h - 2 * r)}a${r} ${r} 0 0 1 ${r} ${-r}z`;

const paths = {
  overview: [rr(3, 3, 7, 9, 1.5), rr(14, 3, 7, 5, 1.5), rr(14, 12, 7, 9, 1.5), rr(3, 16, 7, 5, 1.5)],
  findings: ["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", "M12 8v4", "M12 16h.01"],
  vulnerabilities: ["M8 2l1.9 1.9M14.1 3.9 16 2M9 7.1v-1a3 3 0 1 1 6 0v1", "M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6z", "M12 20v-9", "M6.5 9C4.6 8.8 3 7.1 3 5M6 13H2M3 21c0-2.1 1.7-3.9 3.8-4M21 5c0 2.1-1.6 3.8-3.5 4M22 13h-4M17.2 17c2.1.1 3.8 1.9 3.8 4"],
  agents: [rr(2, 2, 20, 8, 2), rr(2, 14, 20, 8, 2), "M6 6h.01M6 18h.01M10 6h4M10 18h4"],
  enrollment: [c(7.5, 15.5, 5.5), "m21 2-9.6 9.6M15.5 7.5l3 3L22 7l-3-3"],
  rules: ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6", "m9 15 2 2 4-4"],
  access: ["M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2", c(9, 7, 4), "M22 21v-2a4 4 0 0 0-3-3.9M16 3.1a4 4 0 0 1 0 7.8"],
  service: [rr(3, 11, 18, 10, 2), c(12, 5, 2), "M12 7v4M8 16h.01M16 16h.01"],
  audit: ["M3 12a9 9 0 1 0 9-9 9.8 9.8 0 0 0-6.7 2.7L3 8", "M3 3v5h5", "M12 7v5l4 2"],
  search: [c(11, 11, 7.5), "m21 21-4.3-4.3"],
  sparkles: ["M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9z", "M19 3v4M17 5h4M5 17v4M3 19h4"],
  close: ["M18 6 6 18M6 6l12 12"],
  back: ["M19 12H5M12 19l-7-7 7-7"],
  chevronRight: ["m9 18 6-6-6-6"],
  chevronDown: ["m6 9 6 6 6-6"],
  chevronUp: ["m18 15-6-6-6 6"],
  popout: ["M15 3h6v6M10 14 21 3M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"],
  dock: ["M21 10V5a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5", "M15 3v7M14 21h7v-7h-7z"],
  maximize: ["M8 3H5a2 2 0 0 0-2 2v3M21 8V5a2 2 0 0 0-2-2h-3M3 16v3a2 2 0 0 0 2 2h3M16 21h3a2 2 0 0 0 2-2v-3"],
  minimize: ["M5 12h14"],
  sun: [c(12, 12, 4), "M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4"],
  moon: ["M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9z"],
  monitor: [rr(2, 3, 20, 14, 2), "M8 21h8M12 17v4"],
  send: ["m22 2-7 20-4-9-9-4z", "M22 2 11 13"],
  check: ["M20 6 9 17l-5-5"],
  alert: ["m21.7 18-8-14a2 2 0 0 0-3.5 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3z", "M12 9v4M12 17h.01"],
  clock: [c(12, 12, 10), "M12 6v6l4 2"],
  plus: ["M12 5v14M5 12h14"],
  refresh: ["M3 12a9 9 0 0 1 9-9 9.8 9.8 0 0 1 6.7 2.7L21 8", "M21 3v5h-5", "M21 12a9 9 0 0 1-9 9 9.8 9.8 0 0 1-6.7-2.7L3 16", "M8 16H3v5"],
  flame: ["M8.5 14.5A2.5 2.5 0 0 0 11 12c0-1.4-.5-2-1-3-1.1-2.1-.2-4 2-6 .5 2.5 2 4.9 4 6.5 2 1.6 3 3.5 3 5.5a7 7 0 1 1-14 0c0-1.2.4-2.3 1-3a2.5 2.5 0 0 0 2.5 2.5z"],
  logout: ["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "m16 17 5-5-5-5", "M21 12H9"],
  help: [c(12, 12, 10), "M9.1 9a3 3 0 0 1 5.8 1c0 2-3 3-3 3", "M12 17h.01"],
  copy: [rr(9, 9, 13, 13, 2), "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"],
  package: ["m7.5 4.3 9 5.1", "M21 8a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.7l7 4a2 2 0 0 0 2 0l7-4a2 2 0 0 0 1-1.7z", "m3.3 7 8.7 5 8.7-5", "M12 22V12"],
  user: [c(12, 8, 4), "M20 21a8 8 0 0 0-16 0"],
  ban: [c(12, 12, 10), "m4.9 4.9 14.2 14.2"],
  pin: ["M12 17v5", "M9 10.8a2 2 0 0 1-1.1 1.8l-1.8.9A2 2 0 0 0 5 15.2v.8a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.8a2 2 0 0 0-1.1-1.8l-1.8-.9a2 2 0 0 1-1.1-1.8V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"],
  layers: ["m12 2 10 5-10 5L2 7z", "m2 17 10 5 10-5", "m2 12 10 5 10-5"],
  activity: ["M22 12h-4l-3 9L9 3l-3 9H2"],
  filter: ["M22 3H2l8 9.5V19l4 2v-8.5z"],
  tag: ["M12.6 2.6A2 2 0 0 0 11.2 2H4a2 2 0 0 0-2 2v7.2a2 2 0 0 0 .6 1.4l8.7 8.7a2.4 2.4 0 0 0 3.4 0l6.6-6.6a2.4 2.4 0 0 0 0-3.4z", "M7.5 7.5h.01"],
  external: ["M15 3h6v6M10 14 21 3"],
  download: ["M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4", "m7 10 5 5 5-5", "M12 15V3"],
  command: ["M15 6v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3V6a3 3 0 1 0-3 3h12a3 3 0 1 0-3-3"],
} as const;

export type IconName = keyof typeof paths;

export function Icon({ name, size = 18, className }: { name: IconName; size?: number; className?: string }) {
  return (
    <svg className={className} width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor"
      strokeWidth={1.75} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {paths[name].map((d) => <path key={d} d={d} />)}
    </svg>
  );
}
