// A person's picture, or their initials when they have none. The picture is
// served by /api/v1/users/{id}/picture; its version (the `picture` field of
// the person or the session) goes in the URL, so a new picture loads at once
// and an unchanged one comes from the browser's cache.
import { useState } from "react";

/** The demo has no server to serve pictures: it keeps them here, by person. */
export const demoPictures = new Map<string, { version: string; url: string }>();

/** "WW" for Wendy Ward. */
export const initialsOf = (name: string): string =>
  name.split(/\s+/).filter(Boolean).map((w) => w[0]).join("").slice(0, 2).toUpperCase() || "?";

export const pictureSrc = (userId: string, version: string, size: 64 | 256): string =>
  demoPictures.get(userId)?.url ?? `/api/v1/users/${encodeURIComponent(userId)}/picture?size=${size}&v=${encodeURIComponent(version)}`;

/** The picture when there is one (and it loads), else the initials. */
export function Avatar({ userId, name, picture, size = 64, className = "" }: {
  userId: string;
  name: string;
  picture?: string | null | undefined;
  size?: 64 | 256;
  className?: string;
}) {
  // A failed load (the picture was removed meanwhile) falls back to initials until the version changes.
  const [failed, setFailed] = useState<string>();
  const shown = picture && failed !== picture ? picture : undefined;
  return (
    <span className={className || "avatar-face"} aria-hidden="true">
      {shown ? <img className="avatar-img" alt="" src={pictureSrc(userId, shown, size)} onError={() => setFailed(shown)} /> : initialsOf(name)}
    </span>
  );
}
