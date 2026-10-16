// The host's Hardening line (approved screens 6–8): each assignable set as the
// platform decides it, the group that decided it, whether the agent has
// caught up, and why hardening checks may show as unavailable.
import { useResource } from "../../api/client";
import type { Agent, HostRuleSetAssignments } from "../../api/types";
import { factsNote, factsUnavailable, hardeningParts, type HardeningPart } from "../rules/ruleAssignment";

/** Linux hosts only (os-release reported), never imported or revoked ones. */
export const hostAssignmentsPath = (agent: Agent): string | null =>
  agent.os_id && agent.status !== "imported" && agent.status !== "revoked" ? `/api/v1/agents/${encodeURIComponent(agent.id)}/rule-set-assignments` : null;

export function HardeningLine({ parts, facts, okAt }: { parts: HardeningPart[]; facts: string | null | undefined; okAt: string | null | undefined }) {
  return (
    <>
      <dt>Hardening</dt>
      <dd>
        {parts.map((part, i) => (
          <span key={part.name}>
            {i > 0 && " · "}{part.name} {part.on ? "on" : "off"}
            {(part.group || part.note) && <span className="subtle">{part.group && ` (${part.group})`}{part.note && ` · ${part.note}`}</span>}
          </span>
        ))}
      </dd>
      {factsUnavailable(facts) && (
        <dd style={{ gridColumn: "1 / -1" }}>
          <span className="badge badge--warn badge--plain">Hardening facts unavailable</span> <span className="subtle">{factsNote(facts ?? "", okAt)}</span>
        </dd>
      )}
    </>
  );
}

export function HardeningRows({ agent }: { agent: Agent }) {
  const host = useResource<HostRuleSetAssignments>(hostAssignmentsPath(agent));
  if (!host.data || host.data.items.length === 0) return null;
  return <HardeningLine parts={hardeningParts(host.data, agent)} facts={host.data.hardening_facts} okAt={host.data.hardening_facts_ok_at} />;
}

/** A set the host reports `not_assigned`; `text` says what switched it off ("off for
 * Production", "off by default"), null while the platform now says on (pending). */
export function NotAssigned({ text }: { text: string | null }) {
  return (
    <>
      <span className="badge badge--plain" title={text ? `Switched ${text}` : undefined}>Not assigned</span>
      {text && <span className="subtle nowrap">{text}</span>}
    </>
  );
}
