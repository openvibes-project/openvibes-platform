// A row's open cases on the Alarms, Compliance and Vulnerabilities lists:
// "being worked on" means in a case (triage v2).
import { useMemo } from "react";

import { useResource } from "../api/client";
import { useSession } from "../app/session";
import { afterAgent, caseBadges, caseNumber } from "./cases";

type Kind = "alarm" | "compliance_finding" | "vulnerability";

/** Row key to the numbers of the open cases holding it (or its hosts). */
export function useCaseBadges(kind: Kind): Map<string, number[]> {
  const { can } = useSession();
  const active = useResource<{ items: { ref: string; case_number: number }[] }>(can("cases.read") ? `/api/v1/cases/active-items?kind=${kind}` : null);
  return useMemo(() => caseBadges(active.data?.items ?? [], kind === "alarm" ? (ref) => ref : afterAgent), [active.data, kind]);
}

export function CaseBadge({ numbers }: { numbers: number[] | undefined }) {
  const [first, ...rest] = numbers ?? [];
  if (first === undefined) return null;
  return (
    <span className="badge badge--info badge--plain" title={`In open ${numbers?.length === 1 ? "case" : "cases"} ${numbers?.map(caseNumber).join(", ")}`}>
      {caseNumber(first)}{rest.length > 0 && ` +${rest.length}`}
    </span>
  );
}
