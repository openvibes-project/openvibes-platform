// What the group page, the new-group page and the delete dialog share: paths,
// saving, who may write, and the debounced preview.
import { type MouseEvent, useEffect, useState } from "react";

import { invalidate, request } from "../../../api/client";
import type { CreateHostGroup, GroupHost, HostGroup, HostGroupPreview, PreviewHostGroup, UpdateHostGroup } from "../../../api/types";
import { nav } from "../../../app/nav";
import { useSession } from "../../../app/session";
import type { Picked } from "./groupState";

/** Why write controls are off (the server's 403 title for hosts.read held only on some groups). */
export const NEEDS_EVERY_HOST = "Changing host groups needs access to every host";
export const NEEDS_MANAGE = "Changing host groups needs the Manage host groups permission";
/** The server's limit on hosts picked by hand (group_checks.rs MAX_PICKED); also how far a manual group's hosts are loaded. */
export const MAX_PICKED = 10000;

export const groupPath = (id: string) => `/api/v1/host-groups/${encodeURIComponent(id)}`;
export const toList = () => nav.view("/settings", { tab: "host-groups" });
/** A save or delete changes the list, the role page's group picker and rule-set switches. */
export const refreshGroups = () => { invalidate("/api/v1/host-groups"); invalidate("/api/v1/rule-set-assignments"); };

/** POST for a new group, PATCH (with the version read) for an existing one. */
export const saveGroup = (groupId: string, body: CreateHostGroup | UpdateHostGroup): Promise<HostGroup> =>
  groupId === "new" ? request<HostGroup>("POST", "/api/v1/host-groups", body) : request<HostGroup>("PATCH", groupPath(groupId), body);

export function link(view: string, params?: Record<string, string>) {
  return { href: nav.href(view, params), onClick: (e: MouseEvent) => { e.preventDefault(); nav.view(view, params); } };
}

export const picks = (hosts: readonly GroupHost[]): Picked[] => hosts.map((h) => ({ agent_id: h.agent_id, hostname: h.hostname ?? h.agent_id }));

/**
 * Writes need host_groups.manage and hosts.read on every host. `show`: the
 * controls appear (manage held); `reason`: why they are off, if they are.
 */
export function useWriteAccess(): { show: boolean; reason: string | undefined } {
  const { can, canEverywhere } = useSession();
  const show = can("host_groups.manage");
  return { show, reason: !show ? NEEDS_MANAGE : canEverywhere("hosts.read") ? undefined : NEEDS_EVERY_HOST };
}

export type Preview = HostGroupPreview | "failed" | undefined;

/** What saving `body` would change, asked once typing pauses; undefined while unknown, "failed" when the server could not say. */
export function usePreview(path: string, body: PreviewHostGroup | undefined): Preview {
  const key = body ? JSON.stringify(body) : "";
  const [result, setResult] = useState<{ key: string; preview: Exclude<Preview, undefined> }>();
  useEffect(() => {
    if (!key) return;
    let live = true;
    const timer = setTimeout(() => {
      request<HostGroupPreview>("POST", path, JSON.parse(key)).then(
        (preview) => { if (live) setResult({ key, preview }); },
        () => { if (live) setResult({ key, preview: "failed" }); },
      );
    }, 400);
    return () => { live = false; clearTimeout(timer); };
  }, [path, key]);
  return result?.key === key ? result.preview : undefined;
}
