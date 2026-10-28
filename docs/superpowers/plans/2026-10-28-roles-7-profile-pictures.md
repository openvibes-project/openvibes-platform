# Profile pictures: implementation plan (step 7)

**Goal:** screen 7c and the helper of the roles spec (board issue #381, epic #320; spec §9.2, §16 step 7). A person has an optional round picture, shown where their initials were: the account menu, their page and the People list.

**Approach:** a new crate, `openvibes-picture`, converts the upload in a throwaway sandboxed process; the console checks permissions, sends the file over a Unix socket and stores the two WebP results in `console_user_pictures` (migration 0069). The web side adds a crop dialog and an `Avatar` component.

## Plan rulings, 2026-10-28 (step 7)

The spec fixes the limits, storage and serving (§9.2). These fill the gaps.

1. **The helper is socket-activated, one process per upload**, like `openvibes-fetch`: the workspace forbids `unsafe`, so a service cannot adopt a listening socket. The limits (256 MiB, 10 s CPU, 15 s run time, no files, no network) are in the systemd unit, because the console's own system-call filter blocks `setrlimit`. The units ship in the `openvibes-console` RPM (the socket's group is the console's) and the console `Wants=` the socket.
2. **The console links only the wire types.** Decoding (`image`, `gif`, `webp-animation`) is the helper's alone, so a decoder flaw cannot reach the console's memory or database. The console sends the file as it came and never looks inside it.
3. **Extra limit: 200 million pixel-frames** (width x height x frames) for an animation. The spec's 4096 x 4096 and 300 frames alone allow 5 billion, about two minutes of CPU; the cap keeps the worst accepted file near 5 s.
4. **AVIF is not accepted in this step.** The spec lists it, but the pure-Rust decoders do not cover it and the system libdav1d would become a new package dependency, which is the user's call (decision card in the thread). Until then an AVIF file gets "Use a JPEG, PNG, GIF, WebP, BMP or TIFF picture". Only a GIF with more than one frame stays animated; an animated WebP becomes a still.
5. **API.** `PUT /api/v1/users/{id}/picture?x=&y=&size=` takes the original file as the raw body (`application/octet-stream`, a route-level limit of 10 MiB + 4 KiB instead of the global 1 MiB) and answers `{picture: <etag>}`. `DELETE` on the same path answers 204. Both need your own id, or `access.users` and the person inside your share (404 otherwise, as everywhere else). `GET .../picture?size=64|256` is open to any signed-in person.
6. **Serving headers.** `Content-Type: image/webp`, `X-Content-Type-Options: nosniff`, `Content-Disposition: inline`, `Cache-Control: private, no-cache`, a strong `ETag` of `"<hash>-<size>"` and `304` on `If-None-Match`. The spec's per-route `Content-Security-Policy: sandbox; default-src 'none'` is not sent: the console's global middleware sets one policy on every response, which already has no scripts, and a WebP is never rendered as a document.
7. **Versions in URLs.** The people list, a person's page and the session carry `picture` (the ETag, absent when there is none). The web adds it as `v=` to the URL so a new picture loads at once and an old one is cached.
8. **Audit.** `user.picture.set` and `user.picture.removed`, with the person as target; no image bytes are ever written to the log.
9. **Refusals** are 413 `picture_too_large` and 422 `picture_<code>` with the sentence from the helper; a helper that cannot be reached is 503 `picture_unavailable`.
10. **The web crop** sends the original plus the square in original pixels. A file the browser cannot show (TIFF in some browsers, HEIC) cannot be cropped and is refused before upload with a message. The demo has no server: it keeps the chosen file as it is (no crop, no conversion) and shows it in the same places.

## Verification

- `cargo test -p openvibes-picture`: every type, limits, crop, damaged files, wire format.
- `cargo test -p platform-store --test user_pictures`: set, replace, remove, audit, cascade.
- `cargo test -p openvibes-console --test pictures_http`: permissions, refusals, headers, 304, session and list versions, an unreachable helper.
- Web: vitest, `tsc`, lint, the demo e2e (`pictures.spec.ts`).
- `scripts/systemd-e2e.sh` converts a real picture through the installed socket (runs in CI only).
