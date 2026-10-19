// The one place views and object kinds are declared. A new module (threat
// alarms, inventory, agent health) is a view entry and a panel entry here;
// it then gets the rail, the palette, the inspector, floating windows and
// assistant citations for free.
import type { ReactNode } from "react";

import type { Access } from "./session";
import { panelTitle } from "./titles";
import { DashboardsView } from "../dashboards/DashboardsView";
import { WidgetGalleryPanel, WidgetSettingsPanel } from "../dashboards/panels";
import { editorState } from "../dashboards/editor";
import { widgetDefs } from "../dashboards/widgets";
import { ComparePanel } from "../panels/hosts/ComparePanel";
import { AssetGroupPanel } from "../panels/admin/AssetGroupPanel";
import { AuditEventPanel, RetentionPanel } from "../panels/admin/AuditPanels";
import { EnrollmentTokenPanel } from "../panels/admin/EnrollmentTokenPanel";
import { PublishBundle, RuleSetPanel } from "../panels/rules/RuleSetPanel";
import { ServiceAccountPanel } from "../panels/admin/ServiceAccountPanel";
import { AdvisoryPanel } from "../panels/findings/AdvisoryPanel";
import { AlarmPanel } from "../panels/alarms/AlarmPanel";
import { CasePanel, NewCasePanel } from "../panels/cases/CasePanel";
import { AgentPanel } from "../panels/hosts/AgentPanel";
import { SiteRulePanel } from "../panels/rules/SiteRulePanel";
import { PackagePanel, splitPackageId } from "../panels/hosts/PackagePanel";
import { PortPanel, UnitPanel, splitPortId } from "../panels/hosts/PortPanel";
import { FindingPanel, splitFindingId } from "../panels/findings/FindingPanel";
import type { IconName } from "../ui/Icon";
import { Cases } from "../views/investigate/Cases";
import { Settings, settingsAccess } from "../views/admin/settings/Settings";
import { Coverage } from "../views/operate/Coverage";
import { SiteRules } from "../views/operate/SiteRules";
import { About } from "../views/help/About";
import { Agents } from "../views/investigate/Agents";
import { Alarms } from "../views/investigate/Alarms";
import { AlarmSuppressions } from "../views/operate/AlarmSuppressions";
import { Ports, Services } from "../views/investigate/Ports";
import { Software } from "../views/investigate/Software";
import { Findings } from "../views/investigate/Findings";
import { Vulnerabilities } from "../views/investigate/Vulnerabilities";
import { Audit } from "../views/admin/Audit";

type ViewDef = {
  path: string;
  /** Paths below this prefix belong to the view too (e.g. /dashboards/{id}). */
  prefix?: string;
  label: string;
  /** On a phone, under More instead of on the bar (the bar has room for five). */
  phoneMore?: boolean;
  /** A shorter label for the phone bar, when `label` is too long for it. */
  short?: string;
  icon: IconName;
  group: "Investigate" | "Operate" | "Admin" | "Help";
  /** Any of these opens the view. Empty: any signed-in user. */
  access: readonly Access[];
  keys: string;
  render: () => ReactNode;
};

export const views: readonly ViewDef[] = [
  { path: "/", prefix: "/dashboards/", label: "Dashboards", short: "Home", icon: "overview", group: "Investigate", keys: "g d", access: [], render: () => <DashboardsView /> },
  { path: "/alarms", label: "Alarms", icon: "alarm", group: "Investigate", keys: "g m", access: [{ permission: "alarms.read" }], render: () => <Alarms /> },
  { path: "/compliance", label: "Compliance", short: "Comply", icon: "findings", group: "Investigate", keys: "g f", access: [{ permission: "compliance.read" }], render: () => <Findings /> },
  { path: "/vulnerabilities", label: "Vulnerabilities", short: "Vulns", icon: "vulnerabilities", group: "Investigate", keys: "g v", access: [{ permission: "vulnerabilities.read" }], render: () => <Vulnerabilities /> },
  { path: "/agents", label: "Hosts", icon: "agents", group: "Investigate", keys: "g a", access: [{ permission: "hosts.read" }], render: () => <Agents /> },
  { path: "/software", label: "Software", icon: "package", group: "Investigate", phoneMore: true, keys: "g w", access: [{ permission: "hosts.read" }], render: () => <Software /> },
  { path: "/ports", label: "Ports", icon: "activity", group: "Investigate", phoneMore: true, keys: "g o", access: [{ permission: "hosts.read" }], render: () => <Ports /> },
  { path: "/services", label: "Services", icon: "layers", group: "Investigate", phoneMore: true, keys: "g u", access: [{ permission: "hosts.read" }], render: () => <Services /> },
  { path: "/cases", label: "Cases", icon: "cases", group: "Investigate", keys: "g c", access: [{ permission: "cases.read" }], render: () => <Cases /> },
  { path: "/alarm-suppressions", label: "Alarm suppressions", icon: "ban", group: "Operate", keys: "g q", access: [{ permission: "alarms.suppressions.read" }], render: () => <AlarmSuppressions /> },
  { path: "/site-rules", label: "Site rules", icon: "rules", group: "Operate", keys: "g k", access: [{ permission: "site_rules.read" }], render: () => <SiteRules /> },
  { path: "/coverage", label: "Coverage", icon: "rules", group: "Operate", keys: "g t", access: [{ permission: "rules.coverage.read" }], render: () => <Coverage /> },
  { path: "/settings", prefix: "/settings/", label: "Settings", icon: "settings", group: "Admin", keys: "g h", access: settingsAccess, render: () => <Settings /> },
  { path: "/audit", label: "Audit log", icon: "audit", group: "Admin", keys: "g l", access: [{ permission: "audit.read" }], render: () => <Audit /> },
  { path: "/about", label: "About", icon: "help", group: "Help", keys: "g i", access: [], render: () => <About /> },
];

type PanelDef = {
  label: string;
  icon: IconName;
  /** A short title from the id alone, for breadcrumbs and window bars. */
  title: (id: string) => string;
  render: (id: string) => ReactNode;
};

/** The best known name of an object: learned from its panel, else from its id. */
export function objectTitle(ref: { kind: string; id: string }): string {
  return panelTitle(ref) ?? panels[ref.kind]?.title(ref.id) ?? ref.id;
}

export const panels: Readonly<Record<string, PanelDef>> = {
  agent: { label: "Host", icon: "agents", title: (id) => id, render: (id) => <AgentPanel id={id} /> },
  alarm: { label: "Alarm", icon: "alarm", title: (id) => `#${id}`, render: (id) => <AlarmPanel id={id} /> },
  case: { label: "Case", icon: "cases", title: (id) => id === "new" ? "New case" : "Case", render: (id) => id === "new" ? <NewCasePanel /> : <CasePanel id={id} /> },
  finding: { label: "Compliance finding", icon: "findings", title: (id) => splitFindingId(id)[1], render: (id) => <FindingPanel id={id} /> },
  package: { label: "Software", icon: "package", title: (id) => splitPackageId(id)[1], render: (id) => <PackagePanel id={id} /> },
  port: { label: "Port", icon: "activity", title: (id) => { const [protocol, port] = splitPortId(id); return `${port}/${protocol}`; }, render: (id) => <PortPanel id={id} /> },
  compare: { label: "Compare", icon: "agents", title: (id) => id.includes(" ") ? "Compare hosts" : "Compare with…", render: (id) => <ComparePanel id={id} /> },
  unit: { label: "Service", icon: "layers", title: (id) => id, render: (id) => <UnitPanel id={id} /> },
  advisory: { label: "Advisory", icon: "vulnerabilities", title: (id) => id, render: (id) => <AdvisoryPanel id={id} /> },
  "rule-set": { label: "Rule set", icon: "rules", title: (id) => id, render: (id) => <RuleSetPanel id={id} /> },
  "enrollment-token": { label: "Enrollment token", icon: "enrollment", title: (id) => id === "new" ? "New token" : id, render: (id) => <EnrollmentTokenPanel id={id} /> },
  "service-account": { label: "Service account", icon: "service", title: (id) => id === "new" ? "New account" : id, render: (id) => <ServiceAccountPanel id={id} /> },
  "audit-event": { label: "Audit event", icon: "audit", title: (id) => `#${id}`, render: (id) => <AuditEventPanel id={id} /> },
  "site-rule": { label: "Site rule", icon: "rules", title: (id) => { const name = id.slice(id.indexOf("/") + 1); return name === "new" ? "New rule" : name; }, render: (id) => <SiteRulePanel id={id} /> },
  "rule-bundle": { label: "Rule bundle", icon: "rules", title: () => "Publish bundle", render: () => <PublishBundle /> },
  "widget-gallery": { label: "Add widget", icon: "plus", title: () => "Add widget", render: () => <WidgetGalleryPanel /> },
  widget: { label: "Widget", icon: "pencil", title: (id) => `Edit widget · ${(widgetDefs as Partial<Record<string, { label: string }>>)[editorState().draft?.widgets.find((w) => w.id === id)?.type ?? ""]?.label ?? "Widget"}`, render: (id) => <WidgetSettingsPanel id={id} /> },
  "asset-group": { label: "Asset group", icon: "access", title: (id) => id === "new" ? "New group" : id, render: (id) => <AssetGroupPanel id={id} /> },
  "audit-retention": { label: "Audit log", icon: "audit", title: () => "Retention", render: () => <RetentionPanel /> },
};
