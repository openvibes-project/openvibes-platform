export type NavigationGroup = {
  label: string;
  items: readonly NavigationItem[];
};

export type NavigationItem = {
  label: string;
  shortLabel: string;
  path: string;
};

export type ConsolePage = {
  description: string;
  group: string;
  title: string;
};

export type NavigationAccess = {
  permission: string;
  global?: boolean;
};

const pageAccess: Readonly<Record<string, readonly NavigationAccess[]>> = {
  "/": [{ permission: "agents.read" }, { permission: "findings.read" }],
  "/findings": [{ permission: "findings.read" }],
  "/agents": [{ permission: "agents.read" }],
  "/enrollment": [{ permission: "tokens.read", global: true }],
  "/rule-sets": [{ permission: "rules.read", global: true }],
  "/access": [{ permission: "rbac.read", global: true }],
  "/service-accounts": [{ permission: "service_accounts.read", global: true }],
  "/audit": [{ permission: "audit.read", global: true }],
};

export type NavigationCapability = { permission: string; scope: { kind: string } };

const seededPermissions: Readonly<Record<string, readonly string[]>> = {
  viewer: ["agents.read", "findings.read"],
  analyst: ["agents.read", "findings.read", "findings.triage"],
  operator: ["agents.read", "agents.revoke", "findings.read", "rules.upload", "tokens.read", "tokens.create", "tokens.revoke"],
  scoped_operator: ["agents.read", "agents.revoke", "findings.read", "rules.upload", "tokens.read", "tokens.create", "tokens.revoke"],
  admin: ["agents.read", "agents.revoke", "findings.read", "findings.triage", "tokens.read", "tokens.create", "tokens.revoke", "rules.read", "rules.upload", "audit.read", "audit.export", "audit.retention.manage", "rbac.read", "rbac.manage", "asset_groups.manage", "service_accounts.read", "service_accounts.manage"],
};

export function canOpenPage(path: string, capabilities: readonly NavigationCapability[], seeded = false): boolean {
  const requirements = pageAccess[path];
  if (requirements === undefined) return false;
  if (seeded) {
    let persona = "analyst";
    let mode = "mixed";
    try {
      persona = localStorage.getItem("openvibes.dev.persona") ?? persona;
      mode = localStorage.getItem("openvibes.dev.mode") ?? mode;
    } catch {
      // The seeded API uses the same defaults when browser storage is unavailable.
    }
    const permissions = seededPermissions[persona] ?? seededPermissions.analyst ?? [];
    return requirements.some(({ permission }) => permissions.includes(permission)
      && !(mode === "permission_removed" && permission === "agents.read"));
  }
  return requirements.some(({ permission, global }) => capabilities.some((capability) =>
    capability.permission === permission && (!global || capability.scope.kind === "global")));
}

export function visibleNavigationGroups(capabilities: readonly NavigationCapability[], seeded = false): readonly NavigationGroup[] {
  return navigationGroups
    .map((group) => ({ ...group, items: group.items.filter((item) => canOpenPage(item.path, capabilities, seeded)) }))
    .filter((group) => group.items.length > 0);
}

export const navigationGroups: readonly NavigationGroup[] = [
  {
    label: "Workspace",
    items: [{ label: "Overview", shortLabel: "Ov", path: "/" }],
  },
  {
    label: "Investigate",
    items: [
      { label: "Findings", shortLabel: "Fi", path: "/findings" },
      { label: "Agents", shortLabel: "Ag", path: "/agents" },
    ],
  },
  {
    label: "Operate",
    items: [
      { label: "Enrollment", shortLabel: "En", path: "/enrollment" },
      { label: "Rule sets", shortLabel: "Ru", path: "/rule-sets" },
    ],
  },
  {
    label: "Administration",
    items: [
      { label: "Access control", shortLabel: "Ac", path: "/access" },
      { label: "Service accounts", shortLabel: "Sa", path: "/service-accounts" },
      { label: "Audit log", shortLabel: "Au", path: "/audit" },
    ],
  },
] as const;

const pages: Readonly<Record<string, ConsolePage>> = {
  "/login": {
    title: "Sign in",
    group: "Account",
    description: "Authenticate with a local console account.",
  },
  "/": {
    title: "Overview",
    group: "Workspace",
    description: "A permission-aware summary of fleet contact and latest observed matches.",
  },
  "/findings": {
    title: "Findings",
    group: "Investigate",
    description: "Review latest observed matches without implying remediation or compliance state.",
  },
  "/agents": {
    title: "Agents",
    group: "Investigate",
    description: "Browse enrolled agents, contact state, operator labels, and certificate metadata.",
  },
  "/enrollment": {
    title: "Enrollment",
    group: "Operate",
    description: "Create and review bounded, single-use enrollment tokens.",
  },
  "/rule-sets": {
    title: "Rule sets",
    group: "Operate",
    description: "Review and publish pre-signed rule bundles without exposing signing keys.",
  },
  "/access": {
    title: "Access control",
    group: "Administration",
    description: "Review roles, bindings, asset scopes, and effective access.",
  },
  "/service-accounts": {
    title: "Service accounts",
    group: "Administration",
    description: "Manage API identities and their expiring, single-display tokens.",
  },
  "/audit": {
    title: "Audit log",
    group: "Administration",
    description: "Search privileged activity, review retention, and export bounded results.",
  },
};

export const pageRoutes: readonly string[] = Object.keys(pages);

export function resolvePage(path: string): ConsolePage | undefined {
  return pages[path];
}
