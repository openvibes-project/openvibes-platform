// The one place views and object kinds are declared. A new module (threat
// alarms, inventory, agent health) is a view entry and a panel entry here;
// it then gets the rail, the palette, the inspector, floating windows and
// assistant citations for free.
import type { ReactNode } from "react";

import type { Permission } from "../api/types";
import { panelTitle } from "./titles";
import { DashboardsView } from "../dashboards/DashboardsView";
import { WidgetGalleryPanel, WidgetSettingsPanel } from "../dashboards/panels";
import { AssetGroupPanel, PublishBundle, RetentionPanel } from "../panels/AdminPanels";
import { AdvisoryPanel } from "../panels/AdvisoryPanel";
import { AgentPanel } from "../panels/AgentPanel";
import { FindingPanel, splitFindingId } from "../panels/FindingPanel";
import { AuditEventPanel, EnrollmentTokenPanel, RuleSetPanel, ServiceAccountPanel, UserPanel } from "../panels/OpsPanels";
import type { IconName } from "../ui/Icon";
import { Access, Audit, Enrollment, RuleSets, ServiceAccounts } from "../views/Admin";
import { Agents } from "../views/Agents";
import { Findings } from "../views/Findings";
import { Vulnerabilities } from "../views/Vulnerabilities";

export type ViewDef = {
  path: string;
  /** Paths below this prefix belong to the view too (e.g. /dashboards/{id}). */
  prefix?: string;
  label: string;
  icon: IconName;
  group: "Investigate" | "Operate" | "Administer";
  /** Any of these opens the view; `global` requires an unscoped grant. Empty: any signed-in user. */
  access: readonly { permission: Permission; global?: boolean }[];
  keys: string;
  render: () => ReactNode;
};

export const views: readonly ViewDef[] = [
  { path: "/", prefix: "/dashboards/", label: "Dashboards", icon: "overview", group: "Investigate", keys: "g d", access: [], render: () => <DashboardsView /> },
  { path: "/findings", label: "Findings", icon: "findings", group: "Investigate", keys: "g f", access: [{ permission: "findings.read" }], render: () => <Findings /> },
  { path: "/vulnerabilities", label: "Vulnerabilities", icon: "vulnerabilities", group: "Investigate", keys: "g v", access: [{ permission: "vulnerabilities.read" }], render: () => <Vulnerabilities /> },
  { path: "/agents", label: "Agents", icon: "agents", group: "Investigate", keys: "g a", access: [{ permission: "agents.read" }], render: () => <Agents /> },
  { path: "/enrollment", label: "Enrollment", icon: "enrollment", group: "Operate", keys: "g e", access: [{ permission: "tokens.read", global: true }], render: () => <Enrollment /> },
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
  agent: { label: "Agent", icon: "agents", title: (id) => id, render: (id) => <AgentPanel id={id} /> },
  finding: { label: "Finding", icon: "findings", title: (id) => splitFindingId(id)[1], render: (id) => <FindingPanel id={id} /> },
  advisory: { label: "Advisory", icon: "vulnerabilities", title: (id) => id, render: (id) => <AdvisoryPanel id={id} /> },
  "rule-set": { label: "Rule set", icon: "rules", title: (id) => id, render: (id) => <RuleSetPanel id={id} /> },
  "enrollment-token": { label: "Enrollment token", icon: "enrollment", title: (id) => id === "new" ? "New token" : id, render: (id) => <EnrollmentTokenPanel id={id} /> },
  "service-account": { label: "Service account", icon: "service", title: (id) => id === "new" ? "New account" : id, render: (id) => <ServiceAccountPanel id={id} /> },
  "audit-event": { label: "Audit event", icon: "audit", title: (id) => `#${id}`, render: (id) => <AuditEventPanel id={id} /> },
  user: { label: "User", icon: "user", title: (id) => id, render: (id) => <UserPanel id={id} /> },
  "rule-bundle": { label: "Rule bundle", icon: "rules", title: () => "Publish bundle", render: () => <PublishBundle /> },
  "widget-gallery": { label: "Add widget", icon: "plus", title: () => "Add widget", render: () => <WidgetGalleryPanel /> },
  widget: { label: "Widget", icon: "filter", title: (id) => id, render: (id) => <WidgetSettingsPanel id={id} /> },
  "asset-group": { label: "Asset group", icon: "access", title: (id) => id === "new" ? "New group" : id, render: (id) => <AssetGroupPanel id={id} /> },
  "audit-retention": { label: "Audit log", icon: "audit", title: () => "Retention", render: () => <RetentionPanel /> },
};
