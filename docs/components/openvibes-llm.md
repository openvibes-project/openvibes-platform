# openvibes-llm (local model server)

The optional RPM that runs the console assistant's model on the platform
host (assistant spec §3 options A and B, §6, §10; plan AS5). The runtime is llama.cpp's
`llama-server`, built from a pinned source. The platform itself never
depends on it: the console talks to any OpenAI-compatible URL
([platform-assistant.md](platform-assistant.md)). So a newer runtime, or
another one such as vLLM on a GPU server, replaces it without code changes.

| Part | What it is |
|---|---|
| `/usr/libexec/openvibes-llm/llama-server` | Pinned llama.cpp build, CPU (AVX2 baseline, static) |
| `/usr/libexec/openvibes-llm/llama-server-vulkan` | Same source built for Vulkan (NVIDIA, AMD, Intel), in `openvibes-llm-vulkan` |
| `/usr/libexec/openvibes-llm/openvibes-llm-check` | `ExecStartPre=`: refuses to start on bad settings or an unverified model; `--idle-only` for the proxy, `--wait-ready` until the model has loaded (crate `openvibes-llm`) |
| `openvibes-llm.socket` | The unit that is enabled: listens on loopback port 18430 and starts the proxy on the first connection |
| `openvibes-llm-proxy.service` | `systemd-socket-proxyd` to the server's Unix socket; exits after `OPENVIBES_LLM_IDLE` without a request; runs as `openvibes-llm`, sandboxed |
| `openvibes-llm.service` | Hardened unit, `llama-server` on the Unix socket `/run/openvibes-llm/llama.sock`, no network, user `openvibes-llm`; started by the proxy, stopped when it exits |
| `/etc/openvibes/llm.conf` | 0644 root, `%config(noreplace)`: port, idle time, context, threads, GPU layers, parallel requests, default alias |
| `/etc/openvibes/llm-api-key` | 0600 root, generated at first install (64 hex characters); given to the service as a systemd credential |
| `/var/lib/openvibes-llm/models/` | 0775 root:openvibes-admin; models installed read-only (0444) |
| `/var/lib/openvibes-llm/model.conf` | The model in use and its SHA-256, written by `openvibes-admin assistant model install`; read after `llm.conf` |
| `/var/lib/openvibes-llm/tuning.conf` | Optional, `%ghost`: `OPENVIBES_LLM_THREADS` and `OPENVIBES_LLM_GPU_LAYERS`, written by `sudo openvibes-admin helper assistant-tune`; read after `llm.conf`, before `model.conf` |
| `/var/lib/openvibes-llm/tune.json` | Optional, `%ghost`: what `helper assistant-tune` measured and wrote, so it can tell its own values from yours |

Precedence (later `EnvironmentFile=` wins): `llm.conf` < `tuning.conf` < `model.conf`. `tuning.conf` therefore overrides `llm.conf` for `OPENVIBES_LLM_THREADS` and `OPENVIBES_LLM_GPU_LAYERS`. A value in `llm.conf` is operator-set when it differs from the packaged default; when `helper assistant-tune` runs it omits such keys from `tuning.conf`. After changing either value in `llm.conf`, run `sudo openvibes-admin helper assistant-tune` (it leaves your value alone and drops it from `tuning.conf`) and `systemctl restart openvibes-llm.socket` (a running server restarts with it); or delete `/var/lib/openvibes-llm/tuning.conf` to go back to `llm.conf` alone.

A value equal to the packaged default (`OPENVIBES_LLM_THREADS=4`,
`OPENVIBES_LLM_GPU_LAYERS=0`) counts as unset, so the next tune replaces
it. To keep it, pin it in a file of your own that the unit reads last:

```sh
printf 'OPENVIBES_LLM_THREADS=4\n' | sudo tee /etc/openvibes/llm-pin.conf
sudo systemctl edit openvibes-llm     # add the two lines below
#   [Service]
#   EnvironmentFile=/etc/openvibes/llm-pin.conf
sudo systemctl restart openvibes-llm.socket
```

`EnvironmentFile=` lines accumulate, and systemd reads a unit's drop-ins
after the unit file itself, so the drop-in's file comes after `llm.conf`,
`tuning.conf` and `model.conf`; for a variable set in several files the
last one read wins (`systemd.exec(5)`, `EnvironmentFile=`; checked with
systemd 259: `systemctl show -p EnvironmentFiles` lists the drop-in's file
last and its value is the one the service sees). Put only the keys you pin
in that file: anything else in it would override `model.conf` too. Tune
still writes and reports its own thread count; the pin wins at start.

## The pinned build

`scripts/build-llama-server.sh [cpu|vulkan]` builds from
`packaging/llm/llama-cpp.pin`: the upstream llama.cpp release v0.6.0
(commit `d81235049384`), GitHub's source archive of the tag, checked
against its SHA-256. It turns off everything the service does not
use, so none of it is there to be misused:

- `LLAMA_SUBPROCESS=OFF`: removes the server's built-in agent tools
  (`--tools`, including `exec_shell_command`, `write_file`, `edit_file`),
  router mode, and subprocess spawning;
- `GGML_RPC=OFF`: no RPC backend (spec §6);
- `LLAMA_OPENSSL=OFF`: no HTTPS, so no model downloads (`--offline` is
  passed as well);
- `LLAMA_BUILD_UI=OFF`: no web UI;
- static libraries, no dynamic backends (`GGML_BACKEND_DL=OFF`).

The script then fails if the binary imports an `exec*` function other
than `execlp`, `posix_spawn`, `posix_spawnp`, `popen`, or `system`, or
links a TLS library. It still imports `execlp`
for ggml's crash backtrace (it would run `gdb`). The unit turns that off
(`GGML_NO_BACKTRACE=1`) and makes it impossible anyway
(`NoExecPaths=/`). `--rpc` is still listed by `--help` but refuses to
run ("RPC not supported in this build").

Idle sleep (`--sleep-idle-seconds`) has a use-after-free (CVE-2026-43631,
GHSA-6hc7-9rph-cm99). It is off by default, the unit never passes it,
`check-rpm.sh` fails if it does, and `openvibes-llm-check` refuses
`LLAMA_ARG_*`, so it cannot be switched on through the environment either.
v0.6.0 contains upstream #29309, which may fix it; idle sleep stays unused
until an advisory confirms. Idle unloading stops the whole process instead
(below).

To update: pick a newer release tag, resolve its commit, check the
upstream security advisories, update the pin's three values (the pin file
says how to verify them), rebuild, check that every CMake option the
script passes still exists, and run `openvibes-admin assistant eval`
against the result.

## Unit

`openvibes-llm.service` fixes every `llama-server` option itself. It
passes `--host /run/openvibes-llm/llama.sock` (a Unix socket; such paths
are limited to 108 bytes), `--api-key-file` (the credential), `--no-webui`,
`--no-slots`, `--offline`, `--jinja`, `--reasoning off`, and
`--timeout 300`.

`--reasoning off` matters for the bundled Qwen3-4B, a hybrid thinking
model: llama-server's default (`auto`) turns thinking on, the reasoning
uses the whole output limit (96 tokens in the probe, 300 for the small
profile), and most questions return no answer. The client may not send
per-request fields (assistant spec §10), so the switch lives here; the
Vulkan drop-in has it too.

Props changes, metrics, tools, MCP, and media paths stay at their default (off).
`llama-server` also reads `LLAMA_ARG_*` variables, so `openvibes-llm-check`
refuses any `LLAMA_*`, `GGML_*` (except `GGML_NO_BACKTRACE`), `HF_*`, or
`HUGGING*` variable. Without that, `LLAMA_ARG_TOOLS=all` in `llm.conf`
would switch tools on.

The check then validates the settings: the port is 1024–65535, the idle time is `infinity` or 30 s to 24 h
(a whole number with `s`, `min` or `h`; bare is seconds), the context
512–131,072, threads 1–256, GPU layers 0–999, parallel requests 1–16, and
the alias is `[A-Za-z0-9._-]{1,64}`. The model must be a `.gguf` file
directly inside the models directory: a regular file, not a link, and not
writable by the service. Its SHA-256 must equal
`OPENVIBES_LLM_MODEL_SHA256`. The check also refuses to run as root.

The sandbox, besides the platform units' usual hardening (see
[packaging.md](packaging.md)):

- `PrivateNetwork=yes`, `IPAddressDeny=any` and
  `RestrictAddressFamilies=AF_UNIX`: no network at all; its only way in is
  the Unix socket `/run/openvibes-llm/llama.sock`;
- `NoExecPaths=/` with `ExecPaths=` covering only its own directory and
  the library directories: no shell, no gdb;
- `ProtectProc=invisible`, `LimitCORE=0` (no core dumps holding prompts);
- `SystemCallErrorNumber=EPERM`;
- `MemoryMax=8G`, `CPUWeight=20`, `IOWeight=20`, `TasksMax=512`, so the
  model never starves ingest or PostgreSQL. Change them with
  `systemctl edit openvibes-llm`.

`openvibes-llm-vulkan` adds a drop-in that runs the Vulkan binary. It
opens only the GPU devices (`DevicePolicy=closed`, DRM and NVIDIA device
nodes), adds the `render` and `video` groups, and turns
`MemoryDenyWriteExecute` off, because GPU drivers compile shaders at run
time. Set `OPENVIBES_LLM_GPU_LAYERS=999` with it.

`/health` and `/v1/models` answer without the API key: `llama-server`
exempts them. They reveal only the alias, on loopback.

## Memory and idle unloading

A loaded model holds memory the whole time it runs: the bundled Qwen3-4B
Q4_K_M at 8192 tokens of context is about 5.4 GB resident (measured:
5,394,560 kB VmRSS; the file's mapped pages count towards it). So the
server runs only while it is used:

```
console --> 127.0.0.1:18430  openvibes-llm.socket (always listening)
              | first connection starts
              v
            openvibes-llm-proxy.service  (systemd-socket-proxyd --exit-idle-time=OPENVIBES_LLM_IDLE)
              | Requires=, After=
              v
            openvibes-llm.service  llama-server on /run/openvibes-llm/llama.sock (StopWhenUnneeded=yes)
```

Why a Unix socket behind the proxy, not a second loopback port: a port is
free whenever the server is stopped, which is most of the time, and any
local user could bind it; the proxy would then hand them the console's
questions, platform data and API key. `/run/openvibes-llm` is the
service's `RuntimeDirectory=` (0750, `openvibes-llm`), the socket in it is
0700 (`UMask=0077`), and the proxy runs as `openvibes-llm` too: only that
account and root can connect. systemd removes the directory whenever the
service stops (a crash included), so a stale socket never blocks the next
start. The public port 18430 is held by systemd's socket unit the whole
time, idle or not, so no one else can take it either; `helper
assistant-tune` and `helper assistant-setup` check that
`openvibes-llm.socket` is active and listens on `127.0.0.1:OPENVIBES_LLM_PORT`
before root sends the server's key there, and refuse otherwise.

The first connection waits in the socket's queue while the check hashes
the model and `llama-server` loads it; `--wait-ready` keeps the server
"starting" until `/health` answers 200, so the proxy passes the
connection on only to a loaded model. After `OPENVIBES_LLM_IDLE` (default
`5min`) without a connection the proxy exits, nothing needs the server any
more, systemd stops it, and its memory is freed. The next question starts
both again.

Measured with user-level copies of the units (Ryzen 9 3900X, 4 threads,
Fedora 44, systemd 259, model file already in the page cache, idle set to
30 s): the first question after idle took 5.8 to 5.9 s (hash 1.5 s, load
2.7 s, readiness poll up to 0.5 s, the 8-token answer under 1 s); a question
to the loaded model 0.7 s; the server stopped 30.1 s after the last request
and was gone 0.4 s later. After `kill -9` of `llama-server` it restarted
(`Restart=on-failure`) on a fresh runtime directory and the next request
was answered. A model file not in the page cache takes longer
to hash and load: up to disk speed for 2.4 GB. Raise the console's
`deadline_seconds` if the first question after idle times out on a slow
host (`helper assistant-tune` measures a loaded server, not a cold start).

In `/etc/openvibes/llm.conf`:

- `OPENVIBES_LLM_IDLE=5min`: time without a question before the model is
  unloaded; `30s` to `24h` (`s`, `min`, `h`). `infinity` keeps it loaded
  (the old behaviour, minus the boot start: the first question still
  loads it).

An `llm.conf` from before idle unloading does not have it; the proxy unit
defaults it to `5min`. After a change, `sudo systemctl restart
openvibes-llm.socket`: the proxy and the server are `PartOf=` it, so a
running server restarts on the new settings and an idle one uses them at
the next question. That is the way to apply any `llm.conf` change, and
members of `openvibes-operators` may do it without a password (polkit, or
`r` on the TUI's `llm` row). The socket keeps 18430 through the restart.
`FlushPending=yes` keeps it listening when the server cannot start (no
model, a changed model file, out of memory): the waiting question is
dropped instead of re-triggering the start until systemd gives up on the
socket. It also flushes when the proxy exits after the idle time: a
question arriving in those few milliseconds gets a backend error and should
be retried (the next one starts the server). The server does not restart itself (`Restart=no`): the next
question starts it.

`OPENVIBES_LLM_PORT` stays the public port, the one the console calls,
but the socket's port is fixed in `openvibes-llm.socket`. To move it:

```sh
sudo systemctl edit openvibes-llm.socket     # add:
#   [Socket]
#   ListenStream=
#   ListenStream=127.0.0.1:PORT
# set OPENVIBES_LLM_PORT=PORT in /etc/openvibes/llm.conf, then
sudo systemctl restart openvibes-llm.socket
sudo openvibes-admin helper assistant-setup --force   # points the console at it
```

Upgrading from a version where `openvibes-llm.service` itself was enabled
on 18430: the package's `%posttrans` disables and stops the old server and
enables `--now openvibes-llm.socket`, once (the new service unit has no
`[Install]`, so it can never be "enabled" again).

## Using it

Out of the box, with the bundled model (`openvibes-llm-model`, which
`dnf install openvibes-llm` pulls in as a recommended package):

```sh
dnf install openvibes-llm
sudo openvibes-admin helper assistant-setup
```

`assistant-setup` hands the generated API key to the console's account
(owner-only, as the console requires), writes `[assistant]` into
`console.toml` (an enabled assistant on the `small` profile whose backend is
`http://127.0.0.1:18430/v1`; other keys and comments stay), stops a running
model server, enables `--now openvibes-llm.socket` (the first request starts
the server), restarts the console, and then tunes the server for
this host (`helper assistant-tune`: CPU threads, and a longer request
deadline when the model is slow here; your own `llm.conf` values stay). It is safe to repeat and
refuses to replace a backend you configured yourself unless you pass
`--force`. Users still need the `assistant.use` permission.

The bundled model is Qwen3-4B Q4_K_M (Apache 2.0, about 2.5 GB, delivered as two
packages under 2 GiB each that `openvibes-llm-model` joins and verifies on
install; if that fails, run `/usr/libexec/openvibes-llm/join-model`; during the
join the host briefly needs about 5 GB free), selected by
the package's `/var/lib/openvibes-llm/model.conf` and pinned by SHA-256 in
`packaging/llm/model.pin`. Without the model package, or to use another
model, install one yourself (the platform never downloads models while
running):

```sh
# Download a GGUF model yourself (see `assistant check` for the recommended
# ones) and take its SHA-256 from the publisher's page.
runuser -u openvibes-admin -- openvibes-admin assistant model install \
    /path/Qwen3.5-4B-Instruct-Q4_K_M.gguf --sha256 <hex> --alias qwen3.5-4b
sudo openvibes-admin helper assistant-setup
```

The resulting console configuration is:

```toml
[assistant]
enabled = true
profile = "small"
lookup_mode = "auto"

[assistant.backend]
url = "http://127.0.0.1:18430/v1"
model = "qwen3-4b"
api_key_file = "/etc/openvibes/llm-api-key"
```

`llm-api-key` is owned by `openvibes-console` (mode 0400) after setup;
`openvibes-llm.service` still receives it as a systemd credential, which
root loads. Run `assistant check` and `assistant eval` as that account:
`sudo -u openvibes-console openvibes-admin assistant check`.

Replacing the model is another `model install` and
`sudo systemctl restart openvibes-llm.socket`; the next question loads it. A model file changed after installation fails the digest check,
and the service does not start.

## How to test

```sh
cargo test --locked -p openvibes-llm            # settings, environment, model checks, binary
cargo test --locked -p openvibes-admin --test assistant model_install
scripts/build-llama-server.sh                    # the pinned CPU build
python3 scripts/tiny-gguf.py /tmp/tiny.gguf      # a 0.5 MiB random-weight test model
```

`scripts/tiny-gguf.py` writes a llama-architecture GGUF with random
weights, arranged so it only ever emits printable ASCII. It proves that
the service loads a model and serves the API. It says nothing about
answer quality: that is what `assistant eval` measures with a real model.

CI: the `fedora` job builds `llama-server` and the RPM, and
`check-rpm.sh` checks the files, the API key, the unit, and the check's
refusals. The `systemd-e2e` job installs `openvibes-llm` under a real
systemd, which checks that:

- the service refuses to start without a model;
- the first request through `openvibes-llm.socket` starts it;
- `model install` works with the tiny model;
- the service runs as its own user with seccomp, `no_new_privs`, no
  capabilities, and the IP deny list;
- chat requests without the API key get 401;
- `openvibes-admin assistant check` passes against it;
- the socket starts it, the proxy does not run as root, it stops after
  30 s idle, and the next request loads it again;
- a model file changed after installation stops the service from
  starting.

Not in CI: the Vulkan build, and answer quality or speed with a real
model, because Hugging Face is not reachable from the build environment.

## Tuning after an upgrade

Installing or upgrading the package starts `openvibes-llm-tune.service`
(a file trigger after all `%posttrans` scriptlets and the restart, no wait, not enabled by anyone). It runs `openvibes-admin
helper assistant-tune --auto`: if the assistant is set up with the bundled
model and the host has no `tuning.conf` yet, it tunes the host; otherwise
it logs why it did nothing (`journalctl -u openvibes-llm-tune`) and exits
0. A host that is tuned already keeps its tuning; run `helper assistant-tune`
to measure again. The unit never passes `--sleep-idle-seconds`.
