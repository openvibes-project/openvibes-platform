# openvibes-picture

Purpose: turns an uploaded profile picture into the two WebP images the
console stores (256 px and 64 px), in a process that has no files, no
network and a hard memory and time limit. The console never decodes an
upload itself. Spec: roles spec §9.2.

## Crate layout

- `lib.rs`: the limits (`MAX_BYTES` 10 MiB, `MAX_SIDE` 4096, `MAX_FRAMES` 300,
  `MAX_WORK` 100 million pixel-frames, `MAX_OUTPUT` 3 MiB), `Crop`, `Output`
  and `Refusal` (with its HTTP problem code and the sentence shown to the
  person).
- `wire.rs`: the request and response bytes. This is all the console links
  (`default-features = false`), so the image decoders are not part of the
  console binary.
- `inspect.rs` and `convert.rs` (feature `decode`, on by default): the type
  from magic bytes, the size and frame count from the header, then the crop,
  resize and WebP encode.
- `main.rs`: reads one request from stdin, writes one response to stdout.

## Wire format

Request: a JSON line `{"x":..,"y":..,"size":..}` (the square to keep, in
pixels of the original), then the original file to the end of the stream (at
most 10 MiB + 1 KiB). Response: a JSON line, then the two images.

```json
{"result":"ok","large":190,"small":78,"animated":false}
{"result":"refused","code":"svg"}
```

Refusal codes, and the console's problem codes (`picture_` + code): `too_large`
(413), `unsupported`, `svg`, `heic`, `dimensions`, `frames`, `work`, `crop`,
`decode`, `output` (all 422).

## What is checked, and when

1. Size, before anything is read: over 10 MiB is `too_large`.
2. The type from the first bytes only (the name and Content-Type are
   ignored): JPEG, PNG, GIF, WebP, BMP, TIFF. Text that starts like markup is
   `svg`; a HEIC/HEIF brand is `heic` ("Convert it to JPEG or PNG first");
   anything else is `unsupported`. AVIF is not accepted yet.
3. The size and frame count from the header: over 4096 per side is
   `dimensions`, over 300 frames `frames`, and for a GIF more than 100
   million pixels in all (width x height x frames) is `work`. The sizes are
   those a person sees: a photo stored sideways with an EXIF orientation is
   measured turned, as the browser shows and crops it. Measured worst cases:
   1024 x 1024 x 300 frames about 5 s; 4096 x 4096 x 5 frames about 2 s and
   230 MB.
4. The crop: a square inside the picture as shown (after the EXIF
   orientation), else `crop`.
5. Decode with the `image` crate's own limits (4096 per side, 192 MiB), turn
   the picture by its EXIF orientation, keep only the square, then resize (Lanczos for a still, a cheaper filter for animation frames) and
   encode lossy WebP at quality 80. A large result over 3 MiB is `output`.

Only a GIF with more than one frame stays animated; every other type, an
animated WebP included, becomes a still of its first frame.

## Sandbox (systemd)

`openvibes-picture.socket` listens on `/run/openvibes-picture/picture.sock`
(root:openvibes-console, 0660, `Accept=yes`, `MaxConnections=4`), so only the
console connects, and a crashing decoder takes down one upload.
`openvibes-picture@.service` runs one process per connection as a
`DynamicUser`, with `PrivateNetwork`, `AF_UNIX` only, `ProtectSystem=strict`,
`PrivateTmp`, `LimitFSIZE=0`, no capabilities, no `@privileged @resources
@network-io` system calls, `PrivateUsers`, `InaccessiblePaths=-/etc/openvibes -/var/lib`,
`MemoryMax=384M`, `LimitCPU=10`, `RuntimeMaxSec=15`, `TasksMax=1`. There is
no `LimitNPROC`: after the switch to the dynamic user the kernel counts the
process itself against it and exec fails. The service's account is in no group, so the
config files (0640, root and a service group) are unreadable to it. The limits
are in the unit because the console's own filter forbids `setrlimit`. The
units ship in the `openvibes-console` RPM, which also starts the socket.

## Dependencies

`image` (decoders: JPEG, PNG, GIF, WebP, BMP, TIFF), `gif` (frame count),
`image-webp` (animated WebP header), `webp-animation` (WebP encoder; builds
libwebp from source, so the RPM build needs a C compiler, which the build
images already have).

## Tests

`crates/openvibes-picture/tests/convert.rs`: every type becomes two WebPs, a
GIF stays animated, the type comes from the bytes, HEIC and SVG are refused,
the size, pixel, frame and work limits, crop validation, damaged files and
the wire round trip. `scripts/systemd-e2e.sh` converts a real picture through
the installed socket and checks an SVG is refused.
