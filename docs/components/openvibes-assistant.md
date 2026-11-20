# openvibes-assistant (assistant container)

The console assistant's model server as its own, optional container
(#643, decision #644), in **early beta** (#646): answers can be wrong, and it
may change between releases. It is the appliance's `openvibes-llm` server
and pinned model ([openvibes-llm.md](openvibes-llm.md)) without systemd,
next to the platform container ([container.md](container.md)).

Not running it means the assistant is off; that is the default.

## Interfaces

- `packaging/assistant/Containerfile`: AlmaLinux 10 minimal plus `libgomp`,
  and three files from the `openvibes-llm` RPM (`llama-server`,
  `openvibes-llm-check`, `model.pin`); its systemd units and the
  `openvibes-admin` it requires stay out. Runs as `openvibes-llm` (976, the
  platform image's account), never root. About 100 MB.
- `packaging/assistant/openvibes-assistant-start`, at every start:
  1. if the pinned model is not on the models volume, downloads it from its
     publisher (`model.pin`'s URL, about 2.7 GB, once) and checks its
     SHA-256; a failed download or check deletes the file and stops, and the
     next start tries again;
  2. makes the model read-only, as the appliance installs it;
  3. waits up to 2 minutes for the key the platform container makes;
  4. runs `openvibes-llm-check` (the appliance's settings and model check);
  5. runs `llama-server` on `127.0.0.1:18430` with the appliance's options
     (no web UI, no slots, offline, `--reasoning off`) and the key.
- `scripts/build-assistant-image.sh RPM_DIR [IMAGE]`: builds it from the
  `openvibes-llm` EL10 RPM; `IMAGE` defaults to `openvibes-assistant:dev`.
- In `packaging/container/compose.yaml`: the `assistant` service, behind the
  `assistant` profile, `network_mode: service:openvibes`, image
  `ghcr.io/openvibes-project/openvibes-assistant:latest`
  (`OPENVIBES_ASSISTANT_IMAGE` picks another).

## Configuration

- **On:** `COMPOSE_PROFILES=assistant` in `.env`, then `docker compose up -d`.
  Off: remove it and `docker compose up -d --remove-orphans` (or
  `docker compose stop assistant`). The console shows the assistant once it
  answers and none while it never has (#653); a browser sees the change on
  its next page load.
- **Network:** it shares the platform container's network, so it listens on
  that container's loopback: only the platform reaches it, nothing is
  published, and the console's loopback rules apply as on the appliance.
- **The key** (ruling on #643): the platform container makes it on its first
  start into the `assistant-key` volume, `root:976 0640`, which this
  container mounts read-only; the console reads its own copy,
  `/etc/openvibes/llm-api-key`, `openvibes-console 0400`. Nothing to set.
- **Tuning:** `OPENVIBES_LLM_THREADS`, `OPENVIBES_LLM_CONTEXT`,
  `OPENVIBES_LLM_GPU_LAYERS` and `OPENVIBES_LLM_PARALLEL` in the service's
  `environment:`, checked by `openvibes-llm-check` as on the appliance
  (defaults 4, 8192, 0, 1).
- **Volumes:** `assistant-models` (the model) and `assistant-key`.

## Failure behaviour

- No network or a changed file at the publisher: the start stops with the
  reason in `docker compose logs assistant`, and the restart policy tries
  again; nothing half-downloaded is kept.
- No key after 2 minutes (the platform container is not running, or runs
  without the key volume): the start stops and says so.
- A model or setting `openvibes-llm-check` refuses: the start stops with its
  message.
- While it is down, the console offers no assistant until it answers again
  after a console restart; one that answered once and then stopped shows
  "unavailable" in the dock.

## How to test

`bash scripts/container-e2e.sh PLATFORM_IMAGE ASSISTANT_IMAGE` (step 5) builds
a variant of the image whose pin names a tiny random-weight model
(`scripts/tiny-gguf.py`) at a `file://` URL, so the download and its check
run without the 2.7 GB model, and checks that:

1. without the profile, the console is pointed at the assistant and both key
   copies have their owners and modes, but a signed-in admin is not offered
   the assistant;
2. with the profile, the assistant downloads and checks its model, serves as
   976, refuses a request without the key, and the console offers it within
   a few minutes.

CI runs it under Docker in the container job.
