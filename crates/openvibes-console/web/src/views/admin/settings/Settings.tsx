// Settings: one tab per area. Each tab opens to its own permission, and the
// Settings page (registry) to any of them, so a new tab is one line here.
import type { ReactNode } from "react";

import { nav, useLocation } from "../../../app/nav";
import { type Access, grantsAny, useSession } from "../../../app/session";
import { RULE_READERS } from "../../../panels/ruleAssignment";
import { Tabs } from "../../../ui/panel";
import { ViewHeader } from "../../../ui/ViewHeader";
import { Access as AccessTab } from "./Access";
import { AssistantSettings } from "./AssistantSettings";
import { Enrollment } from "./Enrollment";
import { RuleSets } from "./RuleSets";
import { ServiceAccounts } from "./ServiceAccounts";

type Tab = { id: string; label: string; access: readonly Access[]; render: () => ReactNode };

const tabs: readonly Tab[] = [
  { id: "access", label: "Access", access: [{ permission: "rbac.read", global: true }], render: () => <AccessTab /> },
  { id: "service-accounts", label: "Service accounts", access: [{ permission: "service_accounts.read", global: true }], render: () => <ServiceAccounts /> },
  { id: "enrollment", label: "Enrollment", access: [{ permission: "tokens.read", global: true }], render: () => <Enrollment /> },
  { id: "rule-sets", label: "Rule sets", access: RULE_READERS, render: () => <RuleSets /> },
  { id: "assistant-settings", label: "Assistant", access: [{ permission: "assistant.admin", global: true }], render: () => <AssistantSettings /> },
];

/** Who may open Settings: anyone who may open one of its tabs. */
export const settingsAccess: readonly Access[] = tabs.flatMap((tab) => tab.access);

export function Settings() {
  const { can } = useSession();
  const { params } = useLocation();
  const allowed = tabs.filter((tab) => grantsAny(can, tab.access));
  const selected = allowed.find((tab) => tab.id === params.get("tab")) ?? allowed[0];
  return (
    <div className="view">
      <ViewHeader title="Settings" />
      <Tabs active={selected?.id ?? ""} onActive={(tab) => nav.setParams({ tab })} tabs={allowed}>
        {(active) => allowed.find((tab) => tab.id === active)?.render()}
      </Tabs>
    </div>
  );
}
