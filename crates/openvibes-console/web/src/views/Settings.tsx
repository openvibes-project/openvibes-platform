// This is the single settings view, which is a single-page form for editing the global settings
// The operate and admin lists: enrollment tokens, rule sets, access,
// service accounts and the audit log. Same table + panel pattern as the rest

import { ViewHeader } from "../ui/ViewHeader";
import { Tabs } from "../ui/panel";
import { Access, ServiceAccounts, Enrollment, RuleSets } from "./Admin";
import { AssistantSettings } from "./AssistantSettings";
import { useSession } from "../app/session";

export function Settings() {
    const { can } = useSession()
  return (
    <div className="view">
      <ViewHeader title="Settings" />
        <Tabs tabs={[
          { id: "access", label: "Access", allowed : can("rbac.read", true) },
          { id: "service-accounts", label: "Service accounts", allowed : can("service_accounts.read", true) },
          { id: "enrollment", label: "Enrollment", allowed : can("tokens.read", true) },
          { id: "rule-sets", label: "Rule sets", allowed : can("rules.read", true) },
          { id: "assistant-settings", label: "Assistant", allowed : can("assistant.admin", true) },
        ].filter((tab) => tab.allowed)}>
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
                if (active === "rule-sets" && can("rules.read", true)) {
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