// The signed feed block and the stale-data warning, as markup (no DOM library
// in vitest; see ui/controls.test.tsx).
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/vulnerabilities", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { FeedBadge, FeedWarning, SignedFeedBlock, type SignedFeed } from "./SignedFeed";

const NOW = Date.parse("2026-11-08T12:00:00Z");
const feed = (over: Partial<SignedFeed> = {}): SignedFeed => ({
  origin: "mirror", feed_id: "site", key_id: "k1", key_fingerprint: "1a2b 3c4d 5e6f 7081 92a3 b4c5 d6e7 f809", pinned: true, sequence: 9,
  created_at: "2026-11-07T00:00:00Z", expires_at: "2026-11-14T00:00:00Z", applied_at: "2026-11-07T01:00:00Z", age_days: 1, state: "current", ...over,
});
const html = (node: React.ReactElement) => renderToStaticMarkup(node).replace(/<!-- -->/g, "");

describe("Signed feed", () => {
  it("shows a green badge while current, amber when old, red once expired", () => {
    expect(html(<FeedBadge feed={feed()} />)).toContain("badge--ok");
    expect(html(<FeedBadge feed={feed({ state: "aging", age_days: 3 })} />)).toContain("Getting old");
    expect(html(<FeedBadge feed={feed({ state: "expired", age_days: 8 })} />)).toContain("badge--bad");
  });

  it("puts a failed mirror read ahead of the age and shows the reason", () => {
    const f = feed({ mirror_error: "kev.json: sha-256 does not match" });
    expect(html(<FeedBadge feed={f} />)).toContain("Mirror problem");
    expect(html(<SignedFeedBlock feed={f} now={NOW} />)).toContain("kev.json: sha-256 does not match");
  });

  it("lists the data date, expiry, origin and key", () => {
    const out = html(<SignedFeedBlock feed={feed()} now={NOW} />);
    expect(out).toContain("Data as of");
    expect(out).toContain("1 day ago");
    expect(out).toContain("site/k1");
    expect(out).toContain("1a2b 3c4d");
    expect(out).toContain("a mirror");
  });

  it("warns only when the data is old, expired or the mirror failed", () => {
    expect(html(<FeedWarning feed={feed()} />)).toBe("");
    expect(html(<FeedWarning feed={feed({ state: "aging", age_days: 3 })} />)).toContain("callout--warn");
    const expired = html(<FeedWarning feed={feed({ state: "expired", age_days: 8 })} />);
    expect(expired).toContain("callout--bad");
    expect(expired).toContain("expired on");
    expect(html(<FeedWarning feed={feed({ mirror_error: "no route" })} />)).toContain("no route");
  });
});
