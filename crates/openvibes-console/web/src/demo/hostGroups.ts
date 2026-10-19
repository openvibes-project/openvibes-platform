// Host-group membership for the demo, as the store decides it: the SQL
// functions console_host_in_group, console_condition_holds and
// console_glob_like (migrations/0053_host_groups.sql), the os_family and
// distribution columns derived there, the rule checks (hosts/group_checks.rs,
// host_group_writes.rs) and the membership sentence (hosts/group_words.rs).

export type Condition = { field: string; negate: boolean; values: string[] };
export type GroupKind = "automatic" | "rule" | "manual";
export type StoredGroup = {
  asset_group_id: string; name: string; kind: GroupKind; description: string;
  /** The rule, in order; empty for manual groups. */
  conditions: Condition[];
  /** Hand-picked agent ids (manual groups). */
  picked: string[];
  upgraded_from_tags: boolean; changed_at: string | null; changed_by: string | null; version: number;
};
/** What membership reads of a host; null is a fact the agent has not reported. */
export type HostFacts = {
  id: string; status: string; hostname?: string | null | undefined; os_id?: string | null | undefined;
  os_version?: string | null | undefined; last_address?: string | null | undefined;
};

/** The store's status is active or revoked/imported; the demo's "stale" is derived there, so it counts as active. */
export const isActive = (h: HostFacts) => h.status === "active" || h.status === "stale";

export const osFamily = (h: HostFacts) => (h.os_id == null ? null : h.os_id === "windows" ? "windows" : "linux");

export function distribution(h: HostFacts): string | null {
  if (h.os_id == null || h.os_version == null) return null;
  const release = h.os_id === "rocky" || h.os_id === "almalinux" ? h.os_version.split(".")[0] : h.os_version;
  return `${h.os_id} ${release}`.toLowerCase();
}

export const osFamilyName = (v: string) => ({ linux: "Linux", windows: "Windows" })[v] ?? v;
const DISTROS: Record<string, string> = { debian: "Debian", ubuntu: "Ubuntu", fedora: "Fedora", rocky: "Rocky Linux", almalinux: "AlmaLinux" };
export function distributionName(v: string): string {
  const at = v.indexOf(" ");
  const first = at < 0 ? v : v.slice(0, at);
  return DISTROS[first] ? DISTROS[first] + (at < 0 ? "" : v.slice(at)) : v;
}

/** `*` matches any run; everything else, `%`, `_` and `\` too, is literal; case is ignored. */
export function globMatches(pattern: string, value: string): boolean {
  const body = pattern.toLowerCase().split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[\\s\\S]*");
  return new RegExp(`^${body}$`).test(value.toLowerCase());
}

/** An address as [bits, width], or null; IPv4 octets without leading zeros, as Rust parses them. */
function parseIp(text: string): [bigint, 32 | 128] | null {
  const v4 = (s: string) => {
    const parts = s.split(".");
    if (parts.length !== 4 || !parts.every((p) => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255)) return null;
    return parts.reduce((n, p) => (n << 8n) | BigInt(p), 0n);
  };
  if (!text.includes(":")) { const n = v4(text); return n === null ? null : [n, 32]; }
  const halves = text.split("::");
  if (halves.length > 2) return null;
  const words = (s: string) => (s === "" ? [] : s.split(":"));
  const head = words(halves[0] ?? "");
  const tail = halves.length === 2 ? words(halves[1] ?? "") : [];
  // An IPv4 tail (::ffff:10.0.0.1) is two groups.
  const last = (halves.length === 2 ? tail : head).at(-1);
  if (last?.includes(".")) {
    const n = v4(last);
    if (n === null) return null;
    (halves.length === 2 ? tail : head).splice(-1, 1, (n >> 16n).toString(16), (n & 0xffffn).toString(16));
  }
  const fill = 8 - head.length - tail.length;
  if (halves.length === 2 && fill < 1) return null;
  const groups = halves.length === 2 ? [...head, ...Array<string>(fill).fill("0"), ...tail] : head;
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;
  return [groups.reduce((n, g) => (n << 16n) | BigInt(`0x${g}`), 0n), 128];
}

/** `10.0.0.0/16`, `10.9.0.44`, `2001:db8::/32`: an address with an optional prefix (host_group_writes.rs is_cidr). */
function parseCidr(value: string): { bits: bigint; width: 32 | 128; prefix: number } | null {
  const [address = "", prefix, ...extra] = value.split("/");
  const ip = parseIp(address);
  if (!ip || extra.length) return null;
  if (prefix === undefined) return { bits: ip[0], width: ip[1], prefix: ip[1] };
  if (!/^\d{1,3}$/.test(prefix) || Number(prefix) > ip[1]) return null;
  return { bits: ip[0], width: ip[1], prefix: Number(prefix) };
}

/** inet's `address <<= cidr`: same family, and the first prefix bits agree. */
export function inCidr(address: string, cidr: string): boolean {
  const ip = parseIp(address);
  const net = parseCidr(cidr);
  if (!ip || !net || ip[1] !== net.width) return false;
  const shift = BigInt(net.width - net.prefix);
  return ip[0] >> shift === net.bits >> shift;
}

/** console_condition_holds: an unknown fact never holds, negated or not. */
export function conditionHolds(h: HostFacts, c: Condition): boolean {
  const any = (fact: string | null | undefined, test: (v: string) => boolean) => fact != null && c.negate !== c.values.some(test);
  switch (c.field) {
    case "os_family": { const f = osFamily(h); return any(f, (v) => v === f); }
    case "distribution": { const d = distribution(h); return any(d, (v) => v === d); }
    case "hostname": return any(h.hostname, (v) => globMatches(v, h.hostname ?? ""));
    case "ip": return any(h.last_address, (v) => inCidr(h.last_address ?? "", v));
    default: return false;
  }
}

/** The DIFF of a preview: a rule of at least one condition, all of which hold. */
export const ruleHolds = (h: HostFacts, conditions: readonly Condition[]) =>
  isActive(h) && conditions.length > 0 && conditions.every((c) => conditionHolds(h, c));

/** console_host_in_group: active hosts only; manual by pick, the others by rule. */
export const inGroup = (h: HostFacts, g: StoredGroup) =>
  isActive(h) && (g.kind === "manual" ? g.picked.includes(h.id) : ruleHolds(h, g.conditions));

// eslint-disable-next-line no-control-regex
export const hasControl = (s: string) => /[\u0000-\u001f\u007f-\u009f]/.test(s);
const chars = (s: string) => [...s].length;
const releasePart = (p: string) => /^[a-z0-9._-]+$/.test(p);
function valueOk(field: string, v: string): boolean {
  switch (field) {
    case "os_family": return v === "linux" || v === "windows";
    case "ip": return parseCidr(v) !== null;
    case "distribution": case "hostname": return chars(v) >= 1 && chars(v) <= 255 && !hasControl(v);
    default: return false;
  }
}

/** The malformed part of a rule: `conditions` (none, or over 16), else the first bad condition's field. */
export function invalidRule(conditions: readonly Condition[]): string | undefined {
  if (conditions.length === 0 || conditions.length > 16) return "conditions";
  const distro = (v: string) => { const at = v.indexOf(" "); return at > 0 && releasePart(v.slice(0, at)) && releasePart(v.slice(at + 1)); };
  const badDistro = conditions.find((c) => c.field === "distribution" && !c.values.every(distro));
  if (badDistro) return badDistro.field;
  return conditions.find((c) => c.values.length < 1 || c.values.length > 64 || !c.values.every((v) => valueOk(c.field, v)))?.field;
}

const WORDS: Record<string, [string, string, string]> = {
  os_family: ["OS family", "is", "is not"], distribution: ["distribution", "is", "is not"],
  hostname: ["hostname", "matches", "does not match"], ip: ["IP address", "is in", "is not in"],
};

/** "Hosts where OS family is Windows and hostname does not match *test*", or "3 hosts picked by hand". */
export function membershipSentence(kind: GroupKind, conditions: readonly Condition[], picked: number): string {
  if (kind === "manual") return `${picked} ${picked === 1 ? "host" : "hosts"} picked by hand`;
  const part = (c: Condition) => {
    const [field, op, negated] = WORDS[c.field] ?? [c.field, "is", "is not"];
    const values = c.values.map((v) => (c.field === "os_family" ? osFamilyName(v) : c.field === "distribution" ? distributionName(v) : v));
    const list = values.length > 1 ? `${values.slice(0, -1).join(", ")} or ${values.at(-1)}` : values.join("");
    return `${field} ${c.negate ? negated : op} ${list}`;
  };
  return `Hosts where ${conditions.map(part).join(" and ")}`;
}
