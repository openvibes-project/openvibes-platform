import { useResource } from "../api/client";
import type { About as AboutInfo, AboutUpdate } from "../api/types";
import { ErrorBox, Loading } from "../ui/bits";
import { ViewHeader } from "../ui/ViewHeader";

/** One sentence for the newer-version check; it never reads as an error. */
function UpdateLine({ update }: { update: AboutUpdate | undefined }) {
  if (!update) return <span className="subtle">Checking for a newer version…</span>;
  switch (update.state) {
    case "available":
      return (
        <span className="row row--wrap">
          <span className="badge badge--warn">Update available</span>
          <span>Version {update.latest_version} is published.</span>
          {update.release_url && <a href={update.release_url} target="_blank" rel="noopener noreferrer">Release notes</a>}
        </span>
      );
    case "up_to_date":
      return <span className="row row--wrap"><span className="badge badge--ok">Up to date</span><span className="subtle">Latest release is {update.latest_version}.</span></span>;
    case "disabled":
      return <span className="subtle">The check is turned off (update_check in the console configuration).</span>;
    default:
      return <span className="subtle">Could not reach the release server. This is not a problem with the platform.</span>;
  }
}

export function About() {
  const about = useResource<AboutInfo>("/api/v1/about");
  const update = useResource<AboutUpdate>("/api/v1/about/update");
  const info = about.data;
  return (
    <div className="view">
      <ViewHeader title="About" />
      <div className="view-pad stack">
        {about.error ? <ErrorBox error={about.error} /> : !info ? <Loading rows={4} /> : (
          <>
            <section className="panel-section">
              <h2 className="section-title">OpenVIBES platform</h2>
              <dl className="kv">
                <dt>Version</dt><dd className="mono">{info.platform_version}</dd>
                <dt>Newer version</dt><dd><UpdateLine update={update.data} /></dd>
              </dl>
            </section>
            <section className="panel-section">
              <h2 className="section-title">Components</h2>
              <dl className="kv">
                <dt>Database schema</dt>
                <dd className="mono">
                  v{info.applied_schema_version ?? "unknown"}
                  {info.applied_schema_version !== undefined && info.applied_schema_version !== info.schema_version && <span className="warn-text"> (this build expects v{info.schema_version})</span>}
                </dd>
                <dt>PostgreSQL</dt><dd className="mono">{info.database_version ?? "unknown"}</dd>
                <dt>Web interface</dt><dd>{info.web_ui_embedded ? `Built into this console (${info.platform_version})` : "Development build, served separately"}</dd>
              </dl>
            </section>
          </>
        )}
      </div>
    </div>
  );
}
