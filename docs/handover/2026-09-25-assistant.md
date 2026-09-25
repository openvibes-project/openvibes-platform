# Handover: the assistant (AS1–AS5) and related work, 2026-09-25

Written by Claude Code at the end of a cloud session. The shared
`../status.md` and `../decisions.md` do not exist in cloud containers, so
this file carries the handover. Copy the relevant lines into them locally
when you next sync.

## State at a glance

| Item | Where | State |
|---|---|---|
| Assistant design (spec) | `docs/specs/2026-09-25-assistant-design.md` | Approved by the user; decisions in §12 |
| Implementation plan AS1–AS8 | `docs/plans/2026-09-25-assistant-implementation.md` | AS1–AS3 and AS5 ticked |
| AS4 plan (console chat panel), **for Codex** | `docs/plans/2026-09-25-assistant-as4-console.md` | Written, not started |
| AS6 (own server elsewhere), AS7 (external provider) | plan | Not started; the user has not asked yet |
| Console fleet grouping (X-M7), specs only | branch `console-current` (00dcd7f, `main` merged in) | Replaces `console-fixes`, which the user will close |
| Assistant AS1–AS5 | openvibes-project/openvibes-platform#28 | Open, CI running; Claude Code watches it |
| READMEs with the logotype, repositories, capabilities, plans | agent: on PR #9's branch; platform and protocol: branch `readme` (no PRs yet) | Pushed |
| Agent security fixes for running as root/SYSTEM | agent repo, openvibes-project/openvibes-agent#9 | Open; macOS CI fix pushed (05325fc); check CI |

## Branches: a linear stack, one PR

Each branch contains the one before it. The PR is for the top one
(`as5-openvibes-llm`), which contains everything:

1. `assistant-design`, 9fdccd8: spec and plan
2. `as1-assistant-client`, 4ff3478: crate `platform-assistant` (config,
   OpenAI-compatible client, probe)
3. `as2-assistant-lookups`, d0d9be2 + a93d0ad: `platform_store::assistant`
   (scoped lookups; **shared crate, separate commit**) and the orchestrator
4. `as3-assistant-eval`, 1ae8a35 + e416c7b: eval fleet, 53-case question
   set, gate, `openvibes-admin assistant check|eval`, and the AS4 plan
5. `as5-openvibes-llm`, 15ebd70 and this handover: `openvibes-llm` RPM,
   `assistant model install`, the pinned `llama-server` build

`origin/main` (6544dab, schema 12) is merged into `as5-openvibes-llm`;
the one conflict, `docs/components/platform-store.md`, keeps both sections.
The lower branches are not updated; use the PR. The stack adds no
migrations.

**PostgreSQL 17 or later is now required for tests:** migration 0012 uses
`GRANT MAINTAIN`. CI uses `postgres:18`. A cloud session's local cluster is
PostgreSQL 16 and cannot reach the PostgreSQL apt repository.

## For Codex: AS4

- Read the AS4 plan first. It lists what `platform-assistant` gives you
  and the review focus.
- **Migration numbers:** `main` is at **0012**, so the next free number is
  **0013**. The AS4 plan and the console specs on `console-current` now say
  so; `console-current` has `main` merged in.
  **Collision:** the OSV plan (`docs/plans/2026-09-25-osv-distributions.md`,
  task D2) also plans 0013. Whichever merges second renumbers.
- `ConsoleConfig` denies unknown fields, so add
  `assistant: Option<AssistantConfig>`.
- **Backend key with `openvibes-llm`:** add
  `LoadCredential=llm-api-key:/etc/openvibes/llm-api-key` to the console
  unit and set
  `api_key_file = "/run/credentials/openvibes-console.service/llm-api-key"`.
  The key file stays root's (0600); `platform-assistant` refuses a key file
  that group or others can read.
- Do not change `platform-assistant` yourself; ask Claude Code. Its
  contract: `answer`, `Settings`, `ChatBackend`, `Event`, `Segment`,
  `Citation`, `StoreLookups`, `AgentScope`.

## What AS5 built (details: `docs/components/openvibes-llm.md`)

- **`openvibes-llm` RPM:** `llama-server` on 127.0.0.1:18430 as
  `openvibes_llm`. `IPAddressDeny=any` and `IPAddressAllow=localhost`;
  `NoExecPaths=/`; no capabilities. The API key reaches the service as a
  systemd credential. `MemoryMax=8G`, `CPUWeight=20`.
- **`openvibes-llm-check` (`ExecStartPre=`):** refuses to run as root.
  Refuses `LLAMA_*`, `GGML_*`, and `HF_*` variables, out-of-range settings,
  and a model that is not a read-only regular `.gguf` file in the models
  directory with the pinned SHA-256.
- **Configuration files:**
  - `/etc/openvibes/llm.conf`: the operator's settings, root-owned.
  - `/var/lib/openvibes-llm/model.conf`: the model selection. It is written
    by `openvibes-admin assistant model install` (run as `openvibes_admin`,
    whose group owns `/var/lib/openvibes-llm`).
- **Pinned build:** `packaging/llm/llama-cpp.pin` (llama.cpp 4df29be4f4c3,
  from the llama-cpp-python 0.3.35 sdist on PyPI, SHA-256 pinned). Built by
  `scripts/build-llama-server.sh` with `LLAMA_SUBPROCESS`, `GGML_RPC`,
  `LLAMA_OPENSSL`, and the web UI off.
- **Tiny test model:** `scripts/tiny-gguf.py`, a stdlib-only random-weight
  model for CI.

## Findings the next agent must know

- **Built-in agent tools:** this `llama-server` has `--tools`, including
  `exec_shell_command`, `write_file`, and `edit_file`, plus MCP. Any
  `LLAMA_ARG_*` variable can switch them on. They are compiled out
  (`LLAMA_SUBPROCESS=OFF`), refused by the check, and blocked by
  `NoExecPaths`. **Keep all three when bumping the pin.** The build script
  fails if the binary imports `execve`, `posix_spawn`, `popen`, or `system`.
  `execlp` remains, for ggml's gdb backtrace; `GGML_NO_BACKTRACE=1` disables
  it.
- **Open endpoints:** `/health` and `/v1/models` answer without the API key
  (hard-coded in llama-server). They reveal only the alias, on loopback.
- **Probe with the tiny model:** it reports "json schema output no",
  expected for random weights. Do not read anything into it.

## Verified, and not verified

Verified in the session:
- fmt, clippy `-D warnings`, docs, and the full workspace tests, with
  PostgreSQL;
- `openvibes-llm` tests as root and as a non-root user;
- the RPMs build and the package contents are right;
- `llama-server` with the unit's exact flags as an unprivileged user,
  followed by a passing `openvibes-admin assistant check`.

**Not verified, first run is in CI** on `as5-openvibes-llm`:
- the unit under a real systemd (the new section at the end of
  `scripts/systemd-e2e.sh`);
- the `fedora` job building llama.cpp (it now installs `gcc-c++` and
  `cmake`).

If the service fails to start there, suspect `MemoryDenyWriteExecute`, the
`~@resources` syscall filter, or `ExecPaths=` first.

**Not verified at all:**
- the Vulkan build and `openvibes-llm-vulkan`;
- any real model: quality, speed, and the AS3 gate. Hugging Face is blocked
  from cloud sessions. The AS3 plan item "measure recommended models" stays
  open. It needs a machine that can download GGUF files: run
  `assistant eval` there and record the results in `eval/models.toml`
  (`tested`).

## Decisions recorded this session

Add these to `../decisions.md` locally.

- **X-M7:** a finding reported by several agents is shown once, and its
  detail lists every endpoint that reported it (console decision 18,
  `/api/v1/findings/groups`).
- **Assistant priorities:** local LLM first; an external provider is
  supported but priority 2 (AS7).
- **Conversations:** kept for 30 days.
- **Runtime:** `llama-server`, kept replaceable. The model is replaceable
  too: the console only speaks the OpenAI-compatible API, and the model is
  a file plus a SHA-256.
- **Model selection:** kept apart from operator settings (`model.conf`
  under `/var/lib`, writable by the admin group; `llm.conf` in `/etc`,
  root's), because `openvibes-admin` runs as `openvibes_admin`.
- **API key:** root's (0600) and handed to services only as systemd
  credentials.

## Useful commands

```sh
eval "$(scripts/test-db.sh)"                   # PostgreSQL for tests (not as root)
cargo test --locked -p platform-assistant -p openvibes-llm
cargo test --locked -p openvibes-admin --test assistant
scripts/build-llama-server.sh                  # needs cmake, gcc-c++, network to PyPI
python3 scripts/tiny-gguf.py /tmp/tiny.gguf
```
