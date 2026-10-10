// The one place views and object kinds are declared. A new module (threat
// alarms, inventory, agent health) is a view entry and a panel entry here;
// it then gets the rail, the palette, the inspector, floating windows and
// assistant citations for free.
import type { ReactNode } from "react";

import type { Permission } from "../api/types";
import { panelTitle } from "./titles";
import { DashboardsView } from "../dashboards/DashboardsView";
import { WidgetGalleryPanel, WidgetSettingsPanel } from "../dashboards/panels";
import { editorState } from "../dashboards/editor";
import { widgetDefs } from "../dashboards/widgets";
import { ComparePanel } from "../panels/ComparePanel";
import { AssetGroupPanel, NewUser, PublishBundle, RetentionPanel } from "../panels/AdminPanels";
import { AdvisoryPanel } from "../panels/AdvisoryPanel";
import { AlarmPanel } from "../panels/AlarmPanel";
import { CasePanel, NewCasePanel } from "../panels/CasePanel";
import { AgentPanel } from "../panels/AgentPanel";
import { SiteRulePanel } from "../panels/SiteRulePanel";
import { PackagePanel, splitPackageId } from "../panels/PackagePanel";
import { PortPanel, UnitPanel, splitPortId } from "../panels/PortPanel";
import { FindingPanel, splitFindingId } from "../panels/FindingPanel";
import { AuditEventPanel, EnrollmentTokenPanel, RuleSetPanel, ServiceAccountPanel, UserPanel } from "../panels/OpsPanels";
import type { IconName } from "../ui/Icon";
import { Cases } from "../views/Cases";
import { Access, Audit, Enrollment, RuleSets, ServiceAccounts } from "../views/Admin";
import { Coverage } from "../views/Coverage";
import { SiteRules } from "../views/SiteRules";
import { AssistantSettings } from "../views/AssistantSettings";
import { About } from "../views/About";
import { Agents } from "../views/Agents";
import { AlarmSuppressions, Alarms } from "../views/Alarms";
import { Ports, Services } from "../views/Ports";
import { Software } from "../views/Software";
import { Findings } from "../views/Findings";
import { Vulnerabilities } from "../views/Vulnerabilities";

export type ViewDef = {
  path: string;
  /** Paths below this prefix belong to the view too (e.g. /dashboards/{id}). */
  prefix?: string;
  label: string;
  /** On a phone, under More instead of on the bar (the bar has room for five). */
  phoneMore?: boolean;
  /** A shorter label for the phone bar, when `label` is too long for it. */
  short?: string;
  icon: IconName;
  group: "Investigate" | "Operate" | "Administer" | "Help";
  /** Any of these opens the view; `global` requires an unscoped grant. Empty: any signed-in user. */
  access: readonly { permission: Permission; global?: boolean }[];
  keys: string;
  render: () => ReactNode;
};

export const views: readonly ViewDef[] = [
  { path: "/", prefix: "/dashboards/", label: "Dashboards", short: "Home", icon: "overview", group: "Investigate", keys: "g d", access: [], render: () => <DashboardsView /> },
  { path: "/alarms", label: "Alarms", icon: "alarm", group: "Investigate", keys: "g m", access: [{ permission: "alarms.read" }], render: () => <Alarms /> },
  { path: "/compliance", label: "Compliance", short: "Comply", icon: "findings", group: "Investigate", keys: "g f", access: [{ permission: "compliance.read" }], render: () => <Findings /> },
  { path: "/vulnerabilities", label: "Vulnerabilities", short: "Vulns", icon: "vulnerabilities", group: "Investigate", keys: "g v", access: [{ permission: "vulnerabilities.read" }], render: () => <Vulnerabilities /> },
  { path: "/agents", label: "Hosts", icon: "agents", group: "Investigate", keys: "g a", access: [{ permission: "agents.read" }], render: () => <Agents /> },
  { path: "/software", label: "Software", icon: "package", group: "Investigate", phoneMore: true, keys: "g w", access: [{ permission: "agents.read" }], render: () => <Software /> },
  { path: "/ports", label: "Ports", icon: "activity", group: "Investigate", phoneMore: true, keys: "g o", access: [{ permission: "agents.read" }], render: () => <Ports /> },
  { path: "/services", label: "Services", icon: "layers", group: "Investigate", phoneMore: true, keys: "g u", access: [{ permission: "agents.read" }], render: () => <Services /> },
  { path: "/cases", label: "Cases", icon: "cases", group: "Investigate", keys: "g c", access: [{ permission: "cases.read" }], render: () => <Cases /> },
  { path: "/enrollment", label: "Enrollment", icon: "enrollment", group: "Operate", keys: "g e", access: [{ permission: "tokens.read", global: true }], render: () => <Enrollment /> },
  { path: "/alarm-suppressions", label: "Alarm suppressions", icon: "ban", group: "Operate", keys: "g q", access: [{ permission: "alarms.read" }], render: () => <AlarmSuppressions /> },
  { path: "/site-rules", label: "Site rules", icon: "rules", group: "Operate", keys: "g k", access: [{ permission: "rules.write", global: true }], render: () => <SiteRules /> },
  { path: "/coverage", label: "Coverage", icon: "rules", group: "Operate", keys: "g t", access: [{ permission: "rules.read", global: true }], render: () => <Coverage /> },
  { path: "/rule-sets", label: "Rule sets", icon: "rules", group: "Operate", keys: "g r", access: [{ permission: "rules.read", global: true }], render: () => <RuleSets /> },
  { path: "/access", label: "Access", icon: "access", group: "Administer", keys: "g p", access: [{ permission: "rbac.read", global: true }], render: () => <Access /> },
  { path: "/service-accounts", label: "Service accounts", icon: "service", group: "Administer", keys: "g s", access: [{ permission: "service_accounts.read", global: true }], render: () => <ServiceAccounts /> },
  { path: "/audit", label: "Audit log", icon: "audit", group: "Administer", keys: "g l", access: [{ permission: "audit.read", global: true }], render: () => <Audit /> },
  { path: "/assistant-settings", label: "Assistant", icon: "sparkles", group: "Administer", keys: "g n", access: [{ permission: "assistant.admin", global: true }], render: () => <AssistantSettings /> },
  { path: "/about", label: "About", icon: "help", group: "Help", keys: "g i", access: [], render: () => <About /> },
];

export type PanelDef = {
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
  user: { label: "User", icon: "user", title: (id) => id === "new" ? "New user" : id, render: (id) => id === "new" ? <NewUser /> : <UserPanel id={id} /> },
  "site-rule": { label: "Site rule", icon: "rules", title: (id) => { const name = id.slice(id.indexOf("/") + 1); return name === "new" ? "New rule" : name; }, render: (id) => <SiteRulePanel id={id} /> },
  "rule-bundle": { label: "Rule bundle", icon: "rules", title: () => "Publish bundle", render: () => <PublishBundle /> },
  "widget-gallery": { label: "Add widget", icon: "plus", title: () => "Add widget", render: () => <WidgetGalleryPanel /> },
  widget: { label: "Widget", icon: "pencil", title: (id) => `Edit widget · ${(widgetDefs as Partial<Record<string, { label: string }>>)[editorState().draft?.widgets.find((w) => w.id === id)?.type ?? ""]?.label ?? "Widget"}`, render: (id) => <WidgetSettingsPanel id={id} /> },
  "asset-group": { label: "Asset group", icon: "access", title: (id) => id === "new" ? "New group" : id, render: (id) => <AssetGroupPanel id={id} /> },
  "audit-retention": { label: "Audit log", icon: "audit", title: () => "Retention", render: () => <RetentionPanel /> },
};
