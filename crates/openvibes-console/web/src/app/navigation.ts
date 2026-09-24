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
