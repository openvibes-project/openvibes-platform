// The one place views and object kinds are declared. A new module (threat
// alarms, inventory, agent health) is a view entry and a panel entry here;
// it then gets the rail, the palette, the inspector, floating windows and
// assistant citations for free.
import type { ReactNode } from "react";

import type { Permission } from "../api/types";
import { panelTitle } from "./titles";
import { DashboardsView } from "../dashboards/DashboardsView";
import { WidgetGalleryPanel, WidgetSettingsPanel } from "../dashboards/panels";
import { AssetGroupPanel, NewUser, PublishBundle, RetentionPanel } from "../panels/AdminPanels";
import { AdvisoryPanel } from "../panels/AdvisoryPanel";
import { AgentPanel } from "../panels/AgentPanel";
import { AlarmPanel } from "../panels/AlarmPanel";
import { PackagePanel, splitPackageId } from "../panels/PackagePanel";
import { FindingPanel, splitFindingId } from "../panels/FindingPanel";
import { AuditEventPanel, EnrollmentTokenPanel, RuleSetPanel, ServiceAccountPanel, UserPanel } from "../panels/OpsPanels";
import type { IconName } from "../ui/Icon";
import { Access, Audit, Enrollment, RuleSets, ServiceAccounts } from "../views/Admin";
import { Agents } from "../views/Agents";
import { AlarmSuppressions, Alarms } from "../views/Alarms";
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
  group: "Investigate" | "Operate" | "Administer";
  /** Any of these opens the view; `global` requires an unscoped grant. Empty: any signed-in user. */
  access: readonly { permission: Permission; global?: boolean }[];
  keys: string;
  render: () => ReactNode;
};

export const views: readonly ViewDef[] = [
  { path: "/", prefix: "/dashboards/", label: "Dashboards", short: "Home", icon: "overview", group: "Investigate", keys: "g d", access: [], render: () => <DashboardsView /> },
  { path: "/findings", label: "Findings", icon: "findings", group: "Investigate", keys: "g f", access: [{ permission: "findings.read" }], render: () => <Findings /> },
  { path: "/alarms", label: "Alarms", icon: "alarm", group: "Investigate", keys: "g m", access: [{ permission: "alarms.read" }], render: () => <Alarms /> },
  { path: "/vulnerabilities", label: "Vulnerabilities", short: "Vulns", icon: "vulnerabilities", group: "Investigate", keys: "g v", access: [{ permission: "vulnerabilities.read" }], render: () => <Vulnerabilities /> },
  { path: "/agents", label: "Hosts", icon: "agents", group: "Investigate", keys: "g a", access: [{ permission: "agents.read" }], render: () => <Agents /> },
  { path: "/software", label: "Software", icon: "package", group: "Investigate", phoneMore: true, keys: "g w", access: [{ permission: "agents.read" }], render: () => <Software /> },
  { path: "/enrollment", label: "Enrollment", icon: "enrollment", group: "Operate", keys: "g e", access: [{ permission: "tokens.read", global: true }], render: () => <Enrollment /> },
  { path: "/alarm-suppressions", label: "Alarm suppressions", icon: "ban", group: "Operate", keys: "g q", access: [{ permission: "alarms.read" }], render: () => <AlarmSuppressions /> },
  { path: "/rule-sets", label: "Rule sets", icon: "rules", group: "Operate", keys: "g r", access: [{ permission: "rules.read", global: true }], render: () => <RuleSets /> },
  { path: "/access", label: "Access", icon: "access", group: "Administer", keys: "g p", access: [{ permission: "rbac.read", global: true }], render: () => <Access /> },
  { path: "/service-accounts", label: "Service accounts", icon: "service", group: "Administer", keys: "g s", access: [{ permission: "service_accounts.read", global: true }], render: () => <ServiceAccounts /> },
  { path: "/audit", label: "Audit log", icon: "audit", group: "Administer", keys: "g l", access: [{ permission: "audit.read", global: true }], render: () => <Audit /> },
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
  finding: { label: "Finding", icon: "findings", title: (id) => splitFindingId(id)[1], render: (id) => <FindingPanel id={id} /> },
  alarm: { label: "Alarm", icon: "alarm", title: (id) => `#${id}`, render: (id) => <AlarmPanel id={id} /> },
  package: { label: "Software", icon: "package", title: (id) => splitPackageId(id)[1], render: (id) => <PackagePanel id={id} /> },
  advisory: { label: "Advisory", icon: "vulnerabilities", title: (id) => id, render: (id) => <AdvisoryPanel id={id} /> },
  "rule-set": { label: "Rule set", icon: "rules", title: (id) => id, render: (id) => <RuleSetPanel id={id} /> },
  "enrollment-token": { label: "Enrollment token", icon: "enrollment", title: (id) => id === "new" ? "New token" : id, render: (id) => <EnrollmentTokenPanel id={id} /> },
  "service-account": { label: "Service account", icon: "service", title: (id) => id === "new" ? "New account" : id, render: (id) => <ServiceAccountPanel id={id} /> },
  "audit-event": { label: "Audit event", icon: "audit", title: (id) => `#${id}`, render: (id) => <AuditEventPanel id={id} /> },
  user: { label: "User", icon: "user", title: (id) => id === "new" ? "New user" : id, render: (id) => id === "new" ? <NewUser /> : <UserPanel id={id} /> },
  "rule-bundle": { label: "Rule bundle", icon: "rules", title: () => "Publish bundle", render: () => <PublishBundle /> },
  "widget-gallery": { label: "Add widget", icon: "plus", title: () => "Add widget", render: () => <WidgetGalleryPanel /> },
  widget: { label: "Widget", icon: "filter", title: (id) => id, render: (id) => <WidgetSettingsPanel id={id} /> },
  "asset-group": { label: "Asset group", icon: "access", title: (id) => id === "new" ? "New group" : id, render: (id) => <AssetGroupPanel id={id} /> },
  "audit-retention": { label: "Audit log", icon: "audit", title: () => "Retention", render: () => <RetentionPanel /> },
};
