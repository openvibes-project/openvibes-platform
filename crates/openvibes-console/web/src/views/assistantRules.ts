// The platform's input rules for the assistant internet setting, mirrored so the
// demo and the form refuse exactly what crates/openvibes-console/src/assistant_internet.rs refuses.

/** `https://` to any host; `http://` only to localhost, loopback, RFC 1918 IPv4 or fc00::/7. */
export function validSearxngUrl(url: string): boolean {
  const https = url.startsWith("https://");
  if (!https && !url.startsWith("http://")) return false;
  if (/[?#@\s\p{Cc}]/u.test(url)) return false;
  const authority = url.slice(https ? 8 : 7).split("/")[0] ?? "";
  let host: string;
  let port: string | undefined;
  if (authority.startsWith("[")) {
    const end = authority.indexOf("]");
    if (end < 0) return false;
    host = authority.slice(1, end);
    const after = authority.slice(end + 1);
    port = after.startsWith(":") ? after.slice(1) : after === "" ? undefined : "bad";
  } else {
    const colon = authority.indexOf(":");
    host = colon < 0 ? authority : authority.slice(0, colon);
    port = colon < 0 ? undefined : authority.slice(colon + 1);
  }
  if (host === "" || (port !== undefined && !(/^\d+$/.test(port) && Number(port) > 0 && Number(port) < 65_536))) return false;
  if (https || host.toLowerCase() === "localhost") return true;
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)?.slice(1).map(Number);
  if (v4 && v4.every((n) => n <= 255)) {
    const [a = 0, b = 0] = v4;
    return a === 127 || a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }
  if (host.includes(":")) return host === "::1" || /^f[cd][0-9a-f]{2}:/i.test(host);
  return false;
}

/** Lowercase LDH labels, 1-63 chars, no edge hyphen, 253 at most; one label is fine. */
export const validDomain = (d: string) =>
  d.length <= 253 && d.split(".").every((l) => /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(l));

/** One domain per line (or comma), trimmed and lowercased. */
export const toDomains = (text: string) => text.split(/[\n,]+/).map((line) => line.trim().toLowerCase()).filter(Boolean);
