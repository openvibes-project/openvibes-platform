import { Fragment, useState, type ReactNode } from "react";

import { useResource } from "../api/client";
import type { About as AboutInfo, AboutUpdate } from "../api/types";
import { ago, date, count, plural } from "../ui/format";
import { ErrorBox, Loading } from "../ui/bits";
import { Icon, type IconName } from "../ui/Icon";
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

const REPO = "https://github.com/openvibes-project/openvibes-platform";
const EXPIRY_WARN_DAYS = 30;

function uptime(startedAt: string, now: number): string {
  const seconds = Math.max(0, Math.floor((now - Date.parse(startedAt)) / 1000));
  const d = Math.floor(seconds / 86400), h = Math.floor((seconds % 86400) / 3600), m = Math.floor((seconds % 3600) / 60);
  return d > 0 ? `${d}d ${h}h` : h > 0 ? `${h}h ${m}m` : `${m}m`;
}

function Card({ icon, title, children }: { icon: IconName; title: string; children: ReactNode }) {
  return (
    <section className="card about-card">
      <div className="card__head"><span className="about-card__icon"><Icon name={icon} size={16} /></span><h2 className="card__title">{title}</h2></div>
      <div className="card__body">{children}</div>
    </section>
  );
}

function Expiry({ at, now }: { at: string; now: number }) {
  const days = Math.floor((Date.parse(at) - now) / 86_400_000);
  const tone = days < 0 ? "bad" : days < EXPIRY_WARN_DAYS ? "warn" : "ok";
  return (
    <span className="row">
      <span>{date(at)}</span>
      <span className={`badge badge--${tone}`}>{days < 0 ? "Expired" : `${plural(days, "day")} left`}</span>
    </span>
  );
}

export function About() {
  const about = useResource<AboutInfo>("/api/v1/about");
  const update = useResource<AboutUpdate>("/api/v1/about/update");
  const info = about.data;
  const [now] = useState(() => Date.now());
  return (
    <div className="view">
      <ViewHeader title="About" />
      <div className="view-pad stack about">
        {about.error ? <ErrorBox error={about.error} /> : !info ? <Loading rows={4} /> : (
          <>
            <section className="card about-hero">
              <img className="about-hero__mark" src={`${import.meta.env.BASE_URL}brand/openvibes-mark.svg`} alt="" />
              <div className="about-hero__text">
                <h2 className="about-hero__name">OpenVIBES</h2>
                <p className="subtle">Vulnerability and exposure monitoring for your fleet.</p>
              </div>
              <div className="about-hero__version">
                <span className="about-hero__number mono">{info.platform_version}</span>
                <UpdateLine update={update.data} />
              </div>
            </section>

            <div className="about-grid">
              <Card icon="service" title="Platform">
                <dl className="kv">
                  <dt>Running on</dt><dd>{info.platform}</dd>
                  <dt>Uptime</dt><dd title={info.started_at}>{uptime(info.started_at, now)}</dd>
                  <dt>Web interface</dt><dd>{info.web_ui_embedded ? "Built into this console" : "Development build, served separately"}</dd>
                </dl>
              </Card>

              <Card icon="layers" title="Database">
                <dl className="kv">
                  <dt>PostgreSQL</dt><dd className="mono">{info.database_version ?? "unknown"}</dd>
                  <dt>Schema</dt>
                  <dd className="row row--wrap">
                    <span className="mono">v{info.applied_schema_version ?? "unknown"}</span>
                    {info.applied_schema_version === info.schema_version
                      ? <span className="badge badge--ok">Current</span>
                      : <span className="badge badge--warn">This build expects v{info.schema_version}</span>}
                  </dd>
                </dl>
              </Card>

              <Card icon="agents" title="Fleet">
                <dl className="kv">
                  <dt>Agents</dt><dd>{count(info.fleet.active)} active, {count(info.fleet.online)} reporting now</dd>
                  <dt>Revoked</dt><dd>{count(info.fleet.revoked)}</dd>
                  <dt>Newest agent</dt><dd className="mono">{info.fleet.newest_agent_version ?? "none yet"}</dd>
                </dl>
              </Card>

              <Card icon="findings" title="Certificate authority">
                {info.certificates.length === 0 ? <p className="subtle">No CA certificate recorded yet.</p> : (
                  <dl className="kv">
                    {info.certificates.map((c) => (
                      <Fragment key={`${c.role}-${c.not_after}`}><dt>{c.role === "root" ? "Root" : "Intermediate"} expires</dt><dd><Expiry at={c.not_after} now={now} /></dd></Fragment>
                    ))}
                  </dl>
                )}
              </Card>
            </div>

            <Card icon="vulnerabilities" title="Vulnerability feeds">
              {info.feeds.length === 0 ? <p className="subtle">No feed has been fetched yet.</p> : (
                <table className="table about-feeds">
                  <thead><tr><th>Feed</th><th className="num">Advisories</th><th>Last checked</th><th>Last changed</th><th>Status</th></tr></thead>
                  <tbody>
                    {info.feeds.map((f) => (
                      <tr key={f.source}>
                        <td className="mono">{f.source}</td>
                        <td className="num">{count(f.advisories)}</td>
                        <td>{ago(f.last_checked_at, now)}</td>
                        <td>{ago(f.last_changed_at, now)}</td>
                        <td>{f.failing ? <span className="badge badge--warn">Last check failed</span> : <span className="badge badge--ok">OK</span>}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </Card>

            <nav className="row row--wrap about-links" aria-label="Project links">
              <a href={REPO} target="_blank" rel="noopener noreferrer">Source on GitHub</a>
              <a href={`${REPO}/releases`} target="_blank" rel="noopener noreferrer">Releases</a>
              <a href={`${REPO}/issues`} target="_blank" rel="noopener noreferrer">Report an issue</a>
            </nav>
          </>
        )}
      </div>
    </div>
  );
}
