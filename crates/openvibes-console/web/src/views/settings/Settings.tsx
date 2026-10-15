// This is the single settings view, which is a single-page form for editing the global settings
// The operate and admin lists: enrollment tokens, rule sets, access,
// service accounts and the audit log. Same table + panel pattern as the rest

import { ViewHeader } from "../../ui/ViewHeader";
import { Tabs } from "../../ui/panel";
import { Access } from "./Access";
import { Enrollment } from "./Enrollment";
import { RuleSets } from "./RuleSets";
import { ServiceAccounts } from "./ServiceAccounts";
import { AssistantSettings } from "./AssistantSettings";
import { useSession } from "../../app/session";
import { nav, useLocation } from "../../app/nav";
import { readsRules } from "../../panels/ruleAssignment";

export function Settings() {
    const { can } = useSession()
    const { params } = useLocation();
    const rulesTab = readsRules(can);

    const tabs = [
        { id: "access", label: "Access", allowed: can("rbac.read", true) },
        { id: "service-accounts", label: "Service accounts", allowed: can("service_accounts.read", true) },
        { id: "enrollment", label: "Enrollment", allowed: can("tokens.read", true) },
        { id: "rule-sets", label: "Rule sets", allowed: rulesTab },
        { id: "assistant-settings", label: "Assistant", allowed: can("assistant.admin", true) },
    ].filter((tab) => tab.allowed);

    const selected = tabs.find((tab) => tab.id === params.get("tab"))?.id
        ?? tabs[0]?.id
        ?? "";
  return (
    <div className="view">
      <ViewHeader title="Settings" />
        <Tabs
            active={selected}
            onActive={(tab) => nav.setParams({ tab })}
            tabs={tabs}
            >
             {(active) => {
                if (active === "access" && can("rbac.read", true)) {
                    return <Access />;
                }
                if (active === "service-accounts" && can("service_accounts.read", true)) {
                    return <ServiceAccounts />;
                }
                if (active === "enrollment" && can("tokens.read", true)) {
                    return <Enrollment />;
                }
                if (active === "rule-sets" && rulesTab) {
                    return <RuleSets />;
                }
                if (active === "assistant-settings" && can("assistant.admin", true)) {
                    return <AssistantSettings />;
                }
                return null;
             }}
        </Tabs>
    </div>
  );
}