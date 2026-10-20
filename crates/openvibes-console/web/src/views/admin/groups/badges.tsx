// Small pieces the host-group screens share: the kind badge, open problems and the preview callout.
import type { HostGroup } from "../../../api/types";
import { Icon } from "../../../ui/Icon";
import type { Preview } from "./groupApi";
import { previewParts } from "./groupState";

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

/** The warn callout "If you save: +N (…), −M (…). … gain access to them."; nothing when nothing changes. */
export function PreviewNote({ preview, verb = "save" }: { preview: Preview; verb?: "save" | "delete" }) {
  if (!preview) return null;
  if (preview === "failed") {
    return <div className="callout group-page__preview" role="status"><Icon name="alert" size={16} /><span>Preview unavailable: who would join or leave is not known.</span></div>;
  }
  const { lead, changes, people } = previewParts(preview, verb);
  if (changes.length === 0) return null;
  return (
    <div className="callout callout--warn group-page__preview" role="status">
      <Icon name="info" size={16} />
      <span>{lead}{changes.map((c, i) => <span key={c.sign}>{i ? ", " : ""}<b>{c.sign}</b> ({c.hosts})</span>)}.{people}</span>
    </div>
  );
}
