// This is the single settings view, which is a single-page form for editing the global settings
// The operate and admin lists: enrollment tokens, rule sets, access,
// service accounts and the audit log. Same table + panel pattern as the rest

import { ViewHeader } from "../ui/ViewHeader";
import { Tabs } from "../ui/panel";
import { Access, ServiceAccounts, Enrollment, RuleSets } from "./Admin";
import { AssistantSettings } from "./AssistantSettings";
import { useSession } from "../app/session";
import { nav, useLocation } from "../app/nav";
import { useResource } from "../api/client";
import type { NetlogDevicePage } from "../api/types";
import { Empty, ErrorBox, Loading } from "../ui/bits";

export function Settings() {
  const { can } = useSession();
  const { params } = useLocation();

  const tabs = [
    { id: "access", label: "Access", allowed: can("rbac.read", true) },
    {
      id: "service-accounts",
      label: "Service accounts",
      allowed: can("service_accounts.read", true),
    },
    {
      id: "enrollment",
      label: "Enrollment",
      allowed: can("tokens.read", true),
    },
    { id: "rule-sets", label: "Rule sets", allowed: can("rules.read", true) },
    {
      id: "assistant-settings",
      label: "Assistant",
      allowed: can("assistant.admin", true),
    },
    {
      id: "netlog-settings",
      label: "Netlog",
      allowed: can("netlog.read", true),
    },
  ].filter((tab) => tab.allowed);

  const selected =
    tabs.find((tab) => tab.id === params.get("tab"))?.id ?? tabs[0]?.id ?? "";
  return (
    <div className='view'>
      <header className='view-header'>
        <div className='view-header__top'>
          <div className='view-header__title'>
            <h1>Settings</h1>
          </div>
        </div>
      </header>
      <Tabs
        active={selected}
        onActive={(tab) => nav.setParams({ tab })}
        tabs={tabs}
      >
        {(active) => {
          if (active === "access" && can("rbac.read", true)) {
            return <Access />;
          }
          if (
            active === "service-accounts" &&
            can("service_accounts.read", true)
          ) {
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
          if (active === "netlog-settings" && can("netlog.read", true)) {
            return <Netlog_settings />;
          }
          return null;
        }}
      </Tabs>
    </div>
  );
}

export function Netlog_settings() {
  const devices = useResource<NetlogDevicePage>("/api/v1/netlog/devices");
  return (
    <div className='view'>
      <ViewHeader title='Netlog Settings' />
      <div className='panel'>
        <div className='panel-content'>
          {devices.error ? (
            <ErrorBox error={devices.error} />
          ) : !devices.data ? (
            <Loading rows={2} />
          ) : devices.data.items.length === 0 ? (
            <Empty title='No registered devices'>
              Registered device connections will appear here :D
            </Empty>
          ) : (
            <p>Registered devices: {devices.data.items.length}</p>
          )}
        </div>
      </div>
    </div>
  );
}
