import type { AssistantInternetSource, AssistantSegment } from "../../api/types";
import type { DemoContext } from "../context";
import { json, severityRank } from "../http";

/** Whether the demo's assistant is on (the server's `state.assistant`); pages offer Ask only then. */
export const ASSISTANT_AVAILABLE = true;

export function registerAssistantRoutes(ctx: DemoContext) {
  const { data, visible, agentById, findings, vulnerabilities, groups, route } = ctx;
  const assistant = (question: string): AssistantSegment[] => {
    const q = question.toLowerCase();
    const text = (value: string): AssistantSegment => ({ kind: "text", text: value });
    const sources = internetSources(question);
    if (sources[0]?.kind === "blocked") {
      return [text("I could not search the web: the query named an internal host, so it was not sent. This is the demo assistant; it answers from synthetic data only.")];
    }
    if (sources.length > 0) {
      return [text("Update OpenSSH to the fixed version and restart sshd; until then, set LoginGraceTime 0 to limit exposure. This is the demo assistant; it answers from synthetic data only.")];
    }
    const cite = (target_kind: string, id: string): AssistantSegment => ({ kind: "citation", target_kind, id, path: "" });
    if (q.includes("stale") || q.includes("offline") || q.includes("contact")) {
      const stale = data.agents.filter((agent) => agent.status === "stale" && visible(agent.id)).slice(0, 4);
      return [text(`${stale.length} of the hosts I looked at have not checked in for over a day. The longest silent ones are `),
        ...stale.flatMap((agent, index) => [cite("agent", agent.id), text(index === stale.length - 1 ? ". Check that the agent service runs and that the host can reach the platform on port 443." : ", ")])];
    }
    if (q.includes("exploit") || q.includes("kev") || q.includes("vulnerab") || q.includes("patch")) {
      const hot = [...new Map(vulnerabilities().filter((v) => v.exploited).map((v) => [v.advisory_id, v])).values()].slice(0, 3);
      return [text("These advisories fix vulnerabilities known to be exploited, so patch them first: "),
        ...hot.flatMap((item, index) => [cite("advisory", item.advisory_id), text(index === hot.length - 1 ? `. Together they affect ${vulnerabilities().filter((v) => v.exploited).length} host findings.` : ", ")])];
    }
    const context = /agent-\d{5}/.exec(question)?.[0];
    if (context !== undefined) {
      const agent = agentById(context);
      const open = findings().filter((finding) => finding.agent_id === context).sort((a, b) => (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9));
      const vulns = vulnerabilities().filter((item) => item.agent_id === context);
      return [text("For "), cite("agent", context), text(` (${agent?.status ?? "unknown"}): ${open.length} compliance findings and ${vulns.length} open vulnerabilities. `),
        ...(open[0] ? [text("The most serious compliance finding is "), cite("finding", `${open[0].rule_set_id}/${open[0].rule_id}`), text(` — ${open[0].message.toLowerCase()}.`)] : [text("No compliance findings right now.")])];
    }
    const top = groups()[0];
    return [text("Start with the most severe open compliance finding: "), ...(top ? [cite("finding", `${top.rule_set_id}/${top.rule_id}`), text(`. ${top.latest_message} Open on ${top.triage_counts.open} ${top.triage_counts.open === 1 ? "host" : "hosts"}.`)] : []),
      text(" This is the demo assistant; it answers from synthetic data only.")];
  };

  // A mitigation question about a CVE shows the sources line, as the real
  // assistant does when internet lookups are on.
  const internetSources = (question: string): AssistantInternetSource[] => {
    // A search naming an internal host: the filter keeps it on the platform.
    if (/search the web for .*\.lab\b/i.test(question)) return [{ kind: "blocked", text: "Web search blocked: the query contained internal data", url: null, number: null }];
    const id = /CVE-\d{4}-\d{4,}/.exec(question)?.[0];
    if (id === undefined || !/mitigat|fix|patch|workaround|remediat|protect against/i.test(question)) return [];
    // The demo's unreachable ID: the lookup failed, the answer is local only.
    if (id === "CVE-2099-0001") return [{ kind: "unavailable", text: "Internet lookup unavailable; this answer uses local data only", url: null, number: null }];
    // [web:1] is the OSV page itself, shown once as the reference with its number.
    return [
      { kind: "reference", text: `Looked up ${id} on osv.dev`, url: `https://osv.dev/vulnerability/${id}`, number: 1 },
      { kind: "search", text: `Searched the web for: ${id} mitigation workaround`, url: null, number: null },
      { kind: "result", text: "www.openssh.com", url: "https://www.openssh.com/txt/release-9.8", number: 2 },
    ];
  };

  route("GET", "/api/v1/assistant/status", "assistant.use", () => json({ available: ASSISTANT_AVAILABLE, model: "demo (synthetic answers)", location: "in your browser" }));
  route("POST", "/api/v1/assistant/messages", "assistant.use", (_, __, body) =>
    json({ segments: assistant(String(body.question ?? "")), lookups: [{ name: "fleet", objects: data.agents.length, error: null }], internet: internetSources(String(body.question ?? "")) }));
}
