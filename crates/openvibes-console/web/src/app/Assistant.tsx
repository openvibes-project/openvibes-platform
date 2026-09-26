import { type FormEvent, useEffect, useRef, useState } from "react";

type Segment =
  | { kind: "text"; text: string }
  | { kind: "citation"; target_kind: string; id: string; path: string };
type Lookup = { name: string | null; objects: number; error: string | null };
type Answer = { segments: Segment[]; lookups: Lookup[] };
type Turn = { question: string; answer?: Answer };
type Status = { available: boolean; location: string; model: string };

function answerText(answer: Answer): string {
  return answer.segments.map((segment) => segment.kind === "text"
    ? segment.text
    : `[${segment.target_kind}:${segment.id}]`).join("");
}

export function AssistantPage({ csrfToken }: { csrfToken?: string | undefined }) {
  const [status, setStatus] = useState<Status>();
  const [turns, setTurns] = useState<Turn[]>([]);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const controllerRef = useRef<AbortController | undefined>(undefined);
  const bytes = new TextEncoder().encode(question).length;

  useEffect(() => {
    const controller = new AbortController();
    void fetch("/api/v1/assistant/status", {
      cache: "no-store",
      credentials: "same-origin",
      signal: controller.signal,
    }).then(async (response) => {
      if (!response.ok) throw new Error("Assistant status is unavailable.");
      setStatus(await response.json() as Status);
    }).catch(() => {
      if (!controller.signal.aborted) setMessage("Assistant status is unavailable.");
    });
    return () => controller.abort();
  }, []);

  async function ask(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const prompt = question.trim();
    if (!csrfToken || !prompt || bytes > 4_000 || busy) return;
    setBusy(true);
    setMessage("");
    setQuestion("");
    setTurns((current) => [...current, { question: prompt }]);
    const controller = new AbortController();
    controllerRef.current = controller;
    try {
      const history = turns.slice(-20).flatMap((turn) => turn.answer === undefined
        ? []
        : [{ question: turn.question, answer: answerText(turn.answer) }]);
      const response = await fetch("/api/v1/assistant/messages", {
        method: "POST",
        cache: "no-store",
        credentials: "same-origin",
        signal: controller.signal,
        headers: {
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken,
        },
        body: JSON.stringify({ question: prompt, history }),
      });
      if (!response.ok) {
        const problem = await response.json() as { title?: string };
        throw new Error(problem.title ?? "The assistant could not answer.");
      }
      const answer = await response.json() as Answer;
      setTurns((current) => current.map((turn, index) => index === current.length - 1
        ? { ...turn, answer }
        : turn));
    } catch (error) {
      if (controller.signal.aborted) {
        setTurns((current) => current.slice(0, -1));
        setQuestion(prompt);
        setMessage("Stopped waiting. The model may finish its current request for up to 30 seconds.");
      } else {
        setTurns((current) => current.slice(0, -1));
        setQuestion(prompt);
        setMessage(error instanceof Error ? error.message : "The assistant could not answer.");
      }
    } finally {
      if (controllerRef.current === controller) controllerRef.current = undefined;
      setBusy(false);
    }
  }

  return (
    <section className="assistant-page" aria-labelledby="assistant-title">
      <div className="assistant-page__heading">
        <div>
          <p className="eyebrow">Read-only help</p>
          <h1 id="assistant-title">Assistant</h1>
          <p>Ask a question about agents and findings you can access. Check the linked records before acting.</p>
        </div>
        <button type="button" onClick={() => { controllerRef.current?.abort(); setTurns([]); setQuestion(""); setMessage(""); }} disabled={busy}>
          New chat
        </button>
      </div>

      <p className="assistant-local-notice">
        {status?.location === "own_network" ? "Model on your network" : "Local model"}{status?.model ? ` · ${status.model}` : ""}. Questions and permitted record details go to the configured model endpoint. This chat stays in this tab and is cleared when you reload or sign out.
      </p>
      {status?.available === false && <p className="read-state" role="status">The local model is unavailable. Try again after the model service is running.</p>}
      {message && <p className="auth-inline-error" role="alert">{message}</p>}

      <div className="assistant-chat" aria-label="Conversation">
        {turns.length === 0 ? <p className="read-state">Start with a question such as “Which agents have high severity findings?”</p> : null}
        {turns.map((turn, index) => (
          <article className="assistant-turn" key={`${index}-${turn.question}`}>
            <div className="assistant-turn__question"><strong>You</strong><p>{turn.question}</p></div>
            <div className="assistant-turn__answer" aria-live={busy && index === turns.length - 1 ? "polite" : undefined}>
              <strong>AI draft — check the linked records</strong>
              {turn.answer === undefined ? <p>{busy && index === turns.length - 1 ? "Checking permitted records…" : "No answer was returned."}</p> : (
                <>
                  <p className="assistant-answer-text">{turn.answer.segments.map((segment, part) => segment.kind === "text"
                    ? <span key={part}>{segment.text}</span>
                    : <a key={part} href={segment.path}>{segment.target_kind === "agent" ? "Agent" : segment.target_kind === "finding" ? "Finding" : "Advisory"}: {segment.id}</a>)}</p>
                  <details>
                    <summary>Looked up</summary>
                    {turn.answer.lookups.length === 0 ? <p>No records were looked up.</p> : <ul>{turn.answer.lookups.map((lookup, item) => <li key={`${lookup.name ?? "unknown"}-${item}`}>{lookup.name ?? "Unsupported query"}: {lookup.error ?? `${lookup.objects} records shown`}</li>)}</ul>}
                  </details>
                </>
              )}
            </div>
          </article>
        ))}
      </div>

      <form className="assistant-composer" onSubmit={(event) => void ask(event)}>
        <label htmlFor="assistant-question">Your question</label>
        <textarea id="assistant-question" value={question} onChange={(event) => setQuestion(event.currentTarget.value)} rows={3} maxLength={4_000} aria-describedby="assistant-question-help" />
        <div className="assistant-composer__actions">
          <span id="assistant-question-help">{bytes} / 4,000 UTF-8 bytes · {turns.length} / 20 turns</span>
          {busy ? <button type="button" onClick={() => controllerRef.current?.abort()}>Stop waiting</button> : <button type="submit" disabled={!csrfToken || !question.trim() || bytes > 4_000 || status === undefined || !status.available || turns.length >= 20}>Ask</button>}
        </div>
      </form>
    </section>
  );
}
