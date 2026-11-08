// The signed vulnerability feed (air-gapped sites): how old its data is, shown
// on the About page and as a warning on the Vulnerabilities page. The server
// decides current / aging / expired so every place agrees.
import { useResource } from "../../api/client";
import type { About } from "../../api/types";
import { viewLink } from "../../app/nav";
import { ago, date, plural } from "../../ui/format";
import { Icon } from "../../ui/Icon";

export type SignedFeed = NonNullable<About["signed_feed"]>;

const ORIGIN: Record<string, string> = { mirror: "a mirror", bundle: "an imported bundle" };

/** The badge for the feed's state; a failed mirror read outranks age. */
export function FeedBadge({ feed }: { feed: SignedFeed }) {
  if (feed.mirror_error) return <span className="badge badge--bad">Mirror problem</span>;
  if (feed.state === "expired") return <span className="badge badge--bad">Expired</span>;
  if (feed.state === "aging") return <span className="badge badge--warn">Getting old</span>;
  return <span className="badge badge--ok">Current</span>;
}

/** The "Signed feed" block of the About page's Vulnerability feeds card. */
export function SignedFeedBlock({ feed, now }: { feed: SignedFeed; now: number }) {
  return (
    <section className="signed-feed" aria-label="Signed feed">
      <h3 className="row row--wrap">Signed feed <FeedBadge feed={feed} /></h3>
      <dl className="kv">
        <dt>Data as of</dt><dd>{date(feed.created_at)} <span className="subtle">({feed.age_days === 0 ? "today" : `${plural(feed.age_days, "day")} ago`})</span></dd>
        <dt>Valid until</dt><dd>{date(feed.expires_at)}{feed.state === "expired" && <span className="subtle"> (old data keeps serving)</span>}</dd>
        <dt>Received from</dt><dd>{ORIGIN[feed.origin] ?? feed.origin}, applied {ago(feed.applied_at, now)}</dd>
        <dt>Signing key</dt>
        <dd><span className="mono">{feed.feed_id}/{feed.key_id}</span>{feed.pinned && <span className="subtle"> (pinned from the mirror)</span>}<br /><span className="mono subtle">{feed.key_fingerprint}</span></dd>
        {feed.mirror_checked_at && <><dt>Mirror last read</dt><dd>{ago(feed.mirror_checked_at, now)}</dd></>}
      </dl>
      {feed.mirror_error && <p className="callout callout--bad" role="alert"><Icon name="alert" size={16} /><span>The mirror could not be read: {feed.mirror_error}</span></p>}
    </section>
  );
}

/** The warning line for old data; nothing while the feed is current and the mirror reads fine. */
export function FeedWarning({ feed }: { feed: SignedFeed }) {
  if (feed.state === "current" && !feed.mirror_error) return null;
  const bad = feed.state === "expired" || !!feed.mirror_error;
  const text = feed.state === "expired"
    ? `The vulnerability data expired on ${date(feed.expires_at)} (it is from ${date(feed.created_at)}). Findings may be missing newer advisories.`
    : feed.state === "aging"
      ? `The vulnerability data is ${plural(feed.age_days, "day")} old (from ${date(feed.created_at)}). Newer advisories may be missing.`
      : "The vulnerability data is current.";
  return (
    <div className={`callout ${bad ? "callout--bad" : "callout--warn"}`} role="status">
      <Icon name="alert" size={16} />
      <span>{text}{feed.mirror_error ? ` The mirror could not be read: ${feed.mirror_error}` : ""} <a {...viewLink("/about")}>Details</a></span>
    </div>
  );
}

/** Loads the feed's state and shows the warning; silent while loading, on errors and for direct-fetch sites. */
export function FeedWarningLoader() {
  const about = useResource<About>("/api/v1/about");
  const feed = about.data?.signed_feed;
  return feed ? <div className="view-pad"><FeedWarning feed={feed} /></div> : null;
}
