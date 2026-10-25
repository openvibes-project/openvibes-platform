// A row's open cases on the Alarms, Compliance and Vulnerabilities lists:
// "being worked on" means in a case (triage v2); and a case's status badge.
import { useMemo } from "react";

import { useResource } from "../../api/client";
import { useSession } from "../../app/session";
import { afterAgent, caseBadges, caseNumber, statusBadge } from "./cases";

type Kind = "alarm" | "compliance_finding" | "vulnerability";

/** Row key to the numbers of the open cases holding it (or its hosts). */
export function useCaseBadges(kind: Kind): Map<string, number[]> {
  const { can } = useSession();
  const active = useResource<{ items: { ref: string; case_number: number }[] }>(can("cases.read") ? `/api/v1/cases/active-items?kind=${kind}` : null);
  // A finding from before rule sets is stored `agent//rule`; its row is `~unknown/rule`.
  return useMemo(() => caseBadges(active.data?.items ?? [],
    (ref) => (kind === "alarm" ? ref : afterAgent(ref).replace(/^\//, "~unknown/"))), [active.data, kind]);
}

/** Per host: the open cases holding this rule's or advisory's item on it
 * (`subject`: `rule_set/rule` or the advisory id). */
export function useHostCaseBadges(kind: Exclude<Kind, "alarm">, subject: string): Map<string, number[]> {
  const { can } = useSession();
  const active = useResource<{ items: { ref: string; case_number: number }[] }>(can("cases.read") ? `/api/v1/cases/active-items?kind=${kind}` : null);
  return useMemo(() => caseBadges((active.data?.items ?? []).filter((i) => afterAgent(i.ref) === subject), (ref) => ref.slice(0, ref.indexOf("/"))), [active.data, subject]);
}

/** Per item (`agent/rule_set/rule` or `agent/advisory`): the open cases holding it. */
export function useItemCaseBadges(kind: Exclude<Kind, "alarm">): Map<string, number[]> {
  const { can } = useSession();
  const active = useResource<{ items: { ref: string; case_number: number }[] }>(can("cases.read") ? `/api/v1/cases/active-items?kind=${kind}` : null);
  return useMemo(() => caseBadges(active.data?.items ?? [], (ref) => ref), [active.data]);
}

export function CaseBadge({ numbers }: Readonly<{ numbers: number[] | undefined }>) {
  const [first, ...rest] = numbers ?? [];
  if (first === undefined) return null;
  return (
    <span className="badge badge--info badge--plain" title={`In open ${numbers?.length === 1 ? "case" : "cases"} ${numbers?.map(caseNumber).join(", ")}`}>
      {caseNumber(first)}{rest.length > 0 && ` +${rest.length}`}
    </span>
  );
}

/** A case's status; a case closed before step 5d also says how it ended ("Closed · mitigated"). */
export function CaseStatusBadge({ status, resolution }: { status: string; resolution?: string | null | undefined }) {
  const badge = statusBadge(status, resolution);
  return <span className={`badge badge--${badge.tone}`}>{badge.label}</span>;
}
