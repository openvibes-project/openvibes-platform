// Settings › Enrollment: adding hosts, and the enrollment tokens they use.
import { isDemo, useResource } from "../../../api/client";
import type { AgentCommand, EnrollmentToken } from "../../../api/types";
import { nav, useLocation, useTopPanel } from "../../../app/nav";
import { useSession } from "../../../app/session";
import { tokenState, tokenUsable } from "../../../panels/admin/tokens";
import { DataTable } from "../../../ui/DataTable";
import { Icon } from "../../../ui/Icon";
import { ViewHeader } from "../../../ui/ViewHeader";
import { Ago, Empty, ErrorBox, Loading } from "../../../ui/bits";
import { matches } from "../../../ui/table";
import { toast } from "../../../ui/toast";

/** The demo has no platform to build the install package from. */
function downloadDemoPackage() {
  const url = URL.createObjectURL(new Blob(["#!/bin/sh\n# Demo: the real package carries the platform's fleet token.\n"], { type: "text/x-shellscript" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: "openvibes-agent-install.sh" });
  link.click();
  URL.revokeObjectURL(url);
}

export function Enrollment() {
  const { can } = useSession();
  const { params } = useLocation();
  const tokens = useResource<{ items: EnrollmentToken[] }>("/api/v1/enrollment-tokens");
  const top = useTopPanel();
  const all = tokens.data?.items ?? [];
  // Expired, used-up and revoked tokens pile up (each short-lived token
  // stays listed), so only the ones a host can still use show by default.
  const showAll = params.get("all") === "true";
  const hidden = all.filter((t) => !tokenUsable(t)).length;
  const rows = all.filter((t) => (showAll || tokenUsable(t)) && matches([t.label, t.token_id], params.get("q") ?? ""));
  return (
    <div className="view">
      <ViewHeader title="Enrollment" count={rows.length} refresh="/api/v1/enrollment-tokens" placeholder="Filter tokens…"
        chips={[{ label: "Show expired and revoked", param: "all", value: "true", count: hidden }]}
        actions={can("tokens.manage", true) && (<>
          <button type="button" className="button button--primary" onClick={() => nav.open({ kind: "enrollment-token", id: "new" }, true)}><Icon name="plus" size={15} /> New token</button>
        </>)} />
      {can("tokens.installer", true) && all.some((t) => t.standing && !t.revoked) && <AddHost />}
      {tokens.error ? <div className="view-pad"><ErrorBox error={tokens.error} /></div> : !tokens.data ? <Loading /> : rows.length === 0 ? (
        <Empty icon="enrollment" title={all.length === 0 ? "No enrollment tokens" : "No usable enrollment tokens"}>
          {all.length === 0 ? "Create one to let new hosts enroll." : `${hidden} expired or revoked ${hidden === 1 ? "token is" : "tokens are"} hidden. Run openvibes-admin agent command to create the standing token.`}
        </Empty>
      ) : (
        <DataTable label="Enrollment tokens" rows={rows} rowKey={(t) => t.token_id}
          onOpen={(t) => nav.open({ kind: "enrollment-token", id: t.token_id }, true)}
          isOpen={(t) => top?.kind === "enrollment-token" && top.id === t.token_id}
          defaultSort={{ key: "created", direction: "desc" }}
          columns={[
            { key: "label", header: "Label", sort: (t) => t.label, render: (t) => <div className="cell-two"><span>{t.label ?? "Unlabelled"}</span><span className="mono subtle">{t.token_id}</span></div> },
            { key: "state", header: "State", width: "110px", sort: (t) => tokenState(t).label, render: (t) => { const s = tokenState(t); return <span className={`badge badge--${s.tone}`}>{s.label}</span>; } },
            { key: "uses", header: "Uses", width: "110px", sort: (t) => (t.standing ? 0 : t.uses / t.max_uses), render: (t) => t.standing
              ? <span className="num subtle">{t.uses} / no limit</span>
              : <span className="row"><span className="meter"><span style={{ width: `${Math.min(100, (t.uses / t.max_uses) * 100)}%` }} /></span><span className="num subtle">{t.uses}/{t.max_uses}</span></span> },
            { key: "expires", header: "Expires", width: "130px", sort: (t) => (t.standing ? "9999" : t.expires_at), render: (t) => <span className="subtle">{t.standing ? "Never" : <Ago value={t.expires_at} />}</span> },
            { key: "created", header: "Created", width: "130px", hideBelow: 800, sort: (t) => t.created_at, render: (t) => <span className="subtle"><Ago value={t.created_at} /></span> },
          ]} />
      )}
    </div>
  );
}

/** How to add a host: the install package, or the one-line command to copy
 * (install walkthrough, 2026-10-08: hosts are added from the console). Both
 * carry the standing token. The command is copied, not shown: it is long and
 * holds the token. */
function AddHost() {
  const command = useResource<AgentCommand>("/api/v1/agent-command");
  const text = command.data?.command;
  return (
    <section className="view-pad stack" aria-labelledby="add-host">
      <h2 id="add-host" className="section-title">Add a host</h2>
      <p className="subtle">Run either as root on the new host. Both carry the standing token: anyone with it can enroll a host.</p>
      {command.error && <ErrorBox error={command.error} />}
      <div className="row row--wrap">
        {isDemo()
          ? <button type="button" className="button" onClick={downloadDemoPackage} title="A script to copy to the host and run with sudo"><Icon name="download" size={15} /> Install package</button>
          : <a className="button" href="/api/v1/agent-package" download title="A script to copy to the host and run with sudo"><Icon name="download" size={15} /> Install package</a>}
        <button type="button" className="button" disabled={!text} title="A one-line command to paste into a root shell on the host"
          onClick={() => { if (text) { void navigator.clipboard?.writeText(text); toast("Install command copied"); } }}>
          <Icon name="copy" size={15} /> Copy CLI install
        </button>
      </div>
    </section>
  );
}
