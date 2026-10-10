// The assistant as a column you keep open while you work. It offers the
// object on top of the inspector as context, and every citation in an
// answer opens that object beside the conversation.
import { useEffect, useRef, useState } from "react";

import { useResource } from "../api/client";
import type { AssistantInternetSource, AssistantSegment, AssistantStatus } from "../api/types";
import { assistant, useAssistant } from "../app/assistant";
import { nav, useLocation } from "../app/nav";
import { objectTitle, panels } from "../app/registry";
import { useTitles } from "../app/titles";
import { Icon } from "../ui/Icon";

const suggestions = [
  "What should I fix first?",
  "Which hosts are stale?",
  "Which vulnerabilities are being exploited?",
];

function Segments({ segments }: { segments: AssistantSegment[] }) {
  return (
    <p className="assistant__answer">
      {segments.map((segment, index) => segment.kind === "text" ? <span key={index}>{segment.text}</span> : (
        <button key={index} type="button" className="cite" onClick={() => nav.open({ kind: segment.target_kind, id: segment.id })}>
          <Icon name={panels[segment.target_kind]?.icon ?? "layers"} size={12} />
          {objectTitle({ kind: segment.target_kind, id: segment.id })}
        </button>
      ))}
    </p>
  );
}

function Sources({ sources }: { sources: AssistantInternetSource[] | undefined }) {
  if (!sources?.length) return null;
  return (
    <ul className="assistant__sources subtle" aria-label="Sources">
      {sources.map((source, index) => (
        <li key={index}>
          <Icon name={source.kind === "search" ? "search" : source.kind === "unavailable" ? "alert" : "external"} size={11} />
          {source.url ? <a href={source.url} target="_blank" rel="noopener noreferrer">{source.text}</a> : source.text}
        </li>
      ))}
    </ul>
  );
}

export function AssistantDock() {
  const state = useAssistant();
  useTitles();
  const { panels: stack } = useLocation();
  const status = useResource<AssistantStatus>(state.open ? "/api/v1/assistant/status" : null);
  const [draft, setDraft] = useState("");
  const input = useRef<HTMLTextAreaElement>(null);
  const log = useRef<HTMLDivElement>(null);
  const top = stack[stack.length - 1];
  const offer = top && !state.context && panels[top.kind] ? top : undefined;

  useEffect(() => { if (state.open) input.current?.focus(); }, [state.open, state.context]);
  useEffect(() => { log.current?.scrollTo({ top: log.current.scrollHeight, behavior: "smooth" }); }, [state.turns.length, state.busy]);
  if (!state.open) return null;

  const send = () => {
    const question = draft;
    setDraft("");
    void assistant.ask(question);
  };

  return (
    <aside className="assistant" aria-label="Assistant" onKeyDown={(event) => { if (event.key === "Escape") assistant.close(); }}>
      <header className="assistant__head">
        <Icon name="sparkles" size={16} className="accent" />
        <div className="grow">
          <h2>Assistant</h2>
          <p className="subtle assistant__status">
            {status.data ? (status.data.available ? `${status.data.model} · ${status.data.location}` : "The model is not running") : status.error ? "Unavailable" : "Checking…"}
          </p>
        </div>
        {state.turns.length > 0 && <button type="button" className="icon-button" title="New conversation" aria-label="New conversation" onClick={() => assistant.reset()}><Icon name="refresh" size={15} /></button>}
        <button type="button" className="icon-button" aria-label="Close assistant" title="Close (Ctrl+J)" onClick={() => assistant.close()}><Icon name="close" size={16} /></button>
      </header>

      <div className="assistant__log" ref={log} aria-live="polite">
        {state.turns.length === 0 && (
          <div className="assistant__intro">
            <p>Ask about your hosts, alarms, vulnerabilities and compliance findings. Answers use only what your role can see, and never leave your platform.</p>
            <div className="stack">
              {suggestions.map((text) => (
                <button key={text} type="button" className="suggestion" onClick={() => void assistant.ask(text)}>{text}</button>
              ))}
            </div>
          </div>
        )}
        {state.turns.map((turn, index) => (
          <div key={index} className="turn">
            <div className="turn__q">
              {turn.context && <span className="turn__ctx"><Icon name={panels[turn.context.kind]?.icon ?? "layers"} size={11} /> {panels[turn.context.kind]?.title(turn.context.id)}</span>}
              {turn.question}
            </div>
            {turn.segments ? <><Segments segments={turn.segments} /><Sources sources={turn.internet} /></> : turn.error ? <p className="turn__error"><Icon name="alert" size={14} /> {turn.error}</p> : (
              <div className="typing" aria-label="Thinking"><span /><span /><span /></div>
            )}
          </div>
        ))}
      </div>

      <form className="assistant__form" onSubmit={(event) => { event.preventDefault(); send(); }}>
        {state.context ? (
          <div className="context-chip">
            <Icon name={panels[state.context.kind]?.icon ?? "layers"} size={12} />
            <span className="truncate">About {state.contextLabel ?? state.context.id}</span>
            <button type="button" aria-label="Remove context" onClick={() => assistant.clearContext()}><Icon name="close" size={12} /></button>
          </div>
        ) : offer && (
          <button type="button" className="context-offer" onClick={() => assistant.askAbout(offer, objectTitle(offer))}>
            <Icon name="plus" size={12} /> <span className="truncate">Ask about {objectTitle(offer)}</span>
          </button>
        )}
        <div className="assistant__input">
          <textarea ref={input} className="textarea" rows={2} value={draft} placeholder="Ask anything…" aria-label="Question"
            onChange={(event) => setDraft(event.target.value)}
            onKeyDown={(event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); send(); } }} />
          <button type="submit" className="icon-button icon-button--send" aria-label="Send" disabled={state.busy || draft.trim() === ""}><Icon name="send" size={16} /></button>
        </div>
      </form>
    </aside>
  );
}
