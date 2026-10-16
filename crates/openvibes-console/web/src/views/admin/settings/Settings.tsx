// Settings: one tab per area. Each tab opens to its own permission, and the
// Settings page (registry) to any of them, so a new tab is one line here.
import type { ReactNode } from "react";

import { nav, useLocation } from "../../../app/nav";
import { type Access, grantsAny, useSession } from "../../../app/session";
import { RULE_READERS } from "../../../panels/rules/ruleAssignment";
import { Tabs } from "../../../ui/panel";
import { Empty } from "../../../ui/bits";
import { RolePage } from "../roles/RolePage";
import { Access as PeopleTab } from "./Access";
import { AssistantSettings } from "./AssistantSettings";
import { Enrollment } from "./Enrollment";
import { HostGroups } from "./HostGroups";
import { Roles } from "./Roles";
import { RuleSets } from "./RuleSets";
import { ServiceAccounts } from "./ServiceAccounts";

type Tab = { id: string; label: string; access: readonly Access[]; render: () => ReactNode };

const tabs: readonly Tab[] = [
  { id: "people", label: "People", access: [{ permission: "access.read" }], render: () => <PeopleTab /> },
  { id: "roles", label: "Roles", access: [{ permission: "access.read" }], render: () => <Roles /> },
  { id: "host-groups", label: "Host groups", access: [{ permission: "access.read" }, { permission: "host_groups.manage" }], render: () => <HostGroups /> },
  { id: "service-accounts", label: "Service accounts", access: [{ permission: "service_accounts.read" }], render: () => <ServiceAccounts /> },
  { id: "enrollment", label: "Enrollment", access: [{ permission: "tokens.read" }], render: () => <Enrollment /> },
  { id: "rule-sets", label: "Rule sets", access: RULE_READERS, render: () => <RuleSets /> },
  { id: "assistant-settings", label: "Assistant", access: [{ permission: "assistant.admin" }], render: () => <AssistantSettings /> },
];

/** Who may open Settings: anyone who may open one of its tabs. */
export const settingsAccess: readonly Access[] = tabs.flatMap((tab) => tab.access);

/**
 * Full pages under /settings/…, shown in place of the Settings header and tabs
 * (approved screens 2 and 5: a breadcrumb back instead). Step 9 adds
 * /settings/people/{id}.
 */
function subPage(path: string): ReactNode | undefined {
  const role = /^\/settings\/roles\/([^/]+)$/.exec(path)?.[1];
  if (role) return <RolePage key={role} roleId={decodeURIComponent(role)} />;
  return undefined;
}

export function Settings() {
  const { can } = useSession();
  const { params, view } = useLocation();
  if (view.startsWith("/settings/")) return subPage(view) ?? <div className="view"><Empty icon="alert" title="Not found">This settings page does not exist.</Empty></div>;
  const allowed = tabs.filter((tab) => grantsAny(can, tab.access));
  const selected = allowed.find((tab) => tab.id === params.get("tab")) ?? allowed[0];
  return (
    <div className="view">
      {/* One search field per tab, so no outer filter (approved screen 1). */}
      <header className="view-header"><div className="view-header__top"><div className="view-header__title"><h1>Settings</h1></div></div></header>
      <Tabs active={selected?.id ?? ""} onActive={(tab) => nav.setParams({ tab })} tabs={allowed}>
        {(active) => allowed.find((tab) => tab.id === active)?.render()}
      </Tabs>
    </div>
  );
}
