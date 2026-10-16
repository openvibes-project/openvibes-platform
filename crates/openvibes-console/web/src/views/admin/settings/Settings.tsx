// Settings: one tab per area. Each tab opens to its own permission, and the
// Settings page (registry) to any of them, so a new tab is one line here.
import type { ReactNode } from "react";

import { nav, useLocation } from "../../../app/nav";
import { type Access, grantsAny, useSession } from "../../../app/session";
import { RULE_READERS } from "../../../panels/rules/ruleAssignment";
import { Tabs } from "../../../ui/panel";
import { ViewHeader } from "../../../ui/ViewHeader";
import { Empty } from "../../../ui/bits";
import { Access as PeopleTab } from "./Access";
import { AssistantSettings } from "./AssistantSettings";
import { Enrollment } from "./Enrollment";
import { HostGroups } from "./HostGroups";
import { RuleSets } from "./RuleSets";
import { ServiceAccounts } from "./ServiceAccounts";

type Tab = { id: string; label: string; access: readonly Access[]; render: () => ReactNode };

const tabs: readonly Tab[] = [
  { id: "people", label: "People", access: [{ permission: "access.read" }], render: () => <PeopleTab /> },
  { id: "host-groups", label: "Host groups", access: [{ permission: "access.read" }, { permission: "host_groups.manage" }], render: () => <HostGroups /> },
  { id: "service-accounts", label: "Service accounts", access: [{ permission: "service_accounts.read" }], render: () => <ServiceAccounts /> },
  { id: "enrollment", label: "Enrollment", access: [{ permission: "tokens.read" }], render: () => <Enrollment /> },
  { id: "rule-sets", label: "Rule sets", access: RULE_READERS, render: () => <RuleSets /> },
  { id: "assistant-settings", label: "Assistant", access: [{ permission: "assistant.admin" }], render: () => <AssistantSettings /> },
];

/** Who may open Settings: anyone who may open one of its tabs. */
export const settingsAccess: readonly Access[] = tabs.flatMap((tab) => tab.access);

/**
 * Full pages under /settings/…, shown in place of the tab panel (tabs stay).
 * Steps 8 and 9 plug in here: /settings/roles/new, /settings/roles/{id} and
 * /settings/people/{id}.
 */
// eslint-disable-next-line @typescript-eslint/no-unused-vars
const subPage = (_path: string): ReactNode | undefined => undefined;

export function Settings() {
  const { can } = useSession();
  const { params, view } = useLocation();
  const sub = view.startsWith("/settings/") ? (subPage(view) ?? <Empty icon="alert" title="Not found">This settings page does not exist.</Empty>) : undefined;
  const allowed = tabs.filter((tab) => grantsAny(can, tab.access));
  const selected = allowed.find((tab) => tab.id === params.get("tab")) ?? allowed[0];
  return (
    <div className="view">
      <ViewHeader title="Settings" />
      <Tabs active={selected?.id ?? ""} onActive={(tab) => view === "/settings" ? nav.setParams({ tab }) : nav.view("/settings", { tab })} tabs={allowed}>
        {(active) => sub ?? allowed.find((tab) => tab.id === active)?.render()}
      </Tabs>
    </div>
  );
}
