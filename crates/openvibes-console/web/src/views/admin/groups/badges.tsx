// Small pieces the host-group list and page share: the kind badge and open problems.
import type { HostGroup } from "../../../api/types";

const KIND: Record<HostGroup["kind"], [string, string]> = {
  automatic: ["badge badge--plain", "Automatic"],
  rule: ["badge badge--accent badge--plain", "Rule"],
  manual: ["badge badge--plain badge--outline", "Manual"],
};

export function KindBadge({ kind }: { kind: HostGroup["kind"] }) {
  const [className, label] = KIND[kind];
  return <span className={className}>{label}</span>;
}

/** "N alarms" / "N critical" badges, or "None open". */
export function Problems({ alarms, critical }: { alarms: number; critical: number }) {
  if (!alarms && !critical) return <span className="subtle">None open</span>;
  return (
    <span className="row group-problems">
      {alarms > 0 && <span className="badge badge--high">{alarms} {alarms === 1 ? "alarm" : "alarms"}</span>}
      {critical > 0 && <span className="badge badge--critical">{critical} critical</span>}
    </span>
  );
}
