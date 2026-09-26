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
| `/usr/libexec/openvibes-llm/openvibes-llm-check` | `ExecStartPre=`: refuses to start on bad settings or an unverified model (crate `openvibes-llm`) |
| `openvibes-llm.service` | Hardened unit, loopback port 18430, user `openvibes_llm` |
| `/etc/openvibes/llm.conf` | 0644 root, `%config(noreplace)`: port, context, threads, GPU layers, parallel requests, default alias |
| `/etc/openvibes/llm-api-key` | 0600 root, generated at first install (64 hex characters); given to the service as a systemd credential |
| `/var/lib/openvibes-llm/models/` | 0775 root:openvibes_admin; models installed read-only (0444) |
| `/var/lib/openvibes-llm/model.conf` | The model in use and its SHA-256, written by `openvibes-admin assistant model install`; read after `llm.conf` |

## The pinned build

`scripts/build-llama-server.sh [cpu|vulkan]` builds from
`packaging/llm/llama-cpp.pin`: the llama.cpp tree vendored in a
llama-cpp-python sdist on PyPI (currently upstream commit `4df29be4f4c3`),
checked against its SHA-256. It turns off everything the service does not
use, so none of it is there to be misused:

- `LLAMA_SUBPROCESS=OFF`: removes the server's built-in agent tools
  (`--tools`, including `exec_shell_command`, `write_file`, `edit_file`),
  router mode, and subprocess spawning;
- `GGML_RPC=OFF`: no RPC backend (spec §6);
- `LLAMA_OPENSSL=OFF`: no HTTPS, so no model downloads (`--offline` is
  passed as well);
- `LLAMA_BUILD_UI=OFF`: no web UI;
- static libraries, no dynamic backends (`GGML_BACKEND_DL=OFF`).

The script then fails if the binary imports `execve`, `posix_spawn`,
`popen`, or `system`, or links a TLS library. It still imports `execlp`
for ggml's crash backtrace (it would run `gdb`). The unit turns that off
(`GGML_NO_BACKTRACE=1`) and makes it impossible anyway
(`NoExecPaths=/`). This version has no idle-sleep option, so the
use-after-free in idle sleep (CVE-2026-43631) cannot be reached.

To update: pick a newer sdist, check the llama.cpp commit in its
CHANGELOG and upstream security advisories, update the pin's three values,
rebuild, and run `openvibes-admin assistant eval` against the result.
A direct upstream tarball can replace the PyPI source later; only the pin
file and the extraction path change.

## Unit

`openvibes-llm.service` fixes every `llama-server` option itself. It
passes `--host 127.0.0.1`, `--api-key-file` (the credential), `--no-webui`,
`--no-slots`, `--offline`, `--jinja`, and `--timeout 300`. Props changes,
metrics, tools, MCP, and media paths stay at their default (off).
`llama-server` also reads `LLAMA_ARG_*` variables, so `openvibes-llm-check`
refuses any `LLAMA_*`, `GGML_*` (except `GGML_NO_BACKTRACE`), `HF_*`, or
`HUGGING*` variable. Without that, `LLAMA_ARG_TOOLS=all` in `llm.conf`
would switch tools on.

The check then validates the settings: the port is 1024–65535, the context
512–131,072, threads 1–256, GPU layers 0–999, parallel requests 1–16, and
the alias is `[A-Za-z0-9._-]{1,64}`. The model must be a `.gguf` file
directly inside the models directory: a regular file, not a link, and not
writable by the service. Its SHA-256 must equal
`OPENVIBES_LLM_MODEL_SHA256`. The check also refuses to run as root.

The sandbox, besides the platform units' usual hardening (see
[packaging.md](packaging.md)):

- `IPAddressDeny=any` and `IPAddressAllow=localhost`: the service can
  neither be reached from nor connect to the network;
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

## Using it

```sh
dnf install ./openvibes-llm-*.rpm            # and openvibes-llm-vulkan for a GPU
# Download a GGUF model yourself (see `assistant check` for the recommended
# ones) and take its SHA-256 from the publisher's page.
runuser -u openvibes_admin -- openvibes-admin assistant model install \
    /path/Qwen3.5-4B-Instruct-Q4_K_M.gguf --sha256 <hex> --alias qwen3.5-4b
systemctl enable --now openvibes-llm
```

The console's configuration then points at it:

```toml
[assistant.backend]
url = "http://127.0.0.1:18430/v1"
model = "qwen3.5-4b"
api_key_file = "/run/credentials/openvibes-console.service/llm-api-key"
```

The console unit receives the key as its own credential
(`LoadCredential=llm-api-key:/etc/openvibes/llm-api-key`), so the file
stays root's. To run `assistant check` or `assistant eval` as
`openvibes_admin`, give it a private copy
(`install -o openvibes_admin -m 0600 /etc/openvibes/llm-api-key …`).

Replacing the model is another `model install` and a restart. A model
file changed after installation fails the digest check, and the service
does not start.

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
- `model install` works with the tiny model;
- the service runs as its own user with seccomp, `no_new_privs`, no
  capabilities, and the IP deny list;
- chat requests without the API key get 401;
- `openvibes-admin assistant check` passes against it;
- a model file changed after installation stops the service from
  starting.

Not in CI: the Vulkan build, and answer quality or speed with a real
model, because Hugging Face is not reachable from the build environment.
