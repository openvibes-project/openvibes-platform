# Assistant on any installation: tune, GPU and a small model

Status: approved in conversation 2026-10-07, waiting for written-spec review.

## 1. Problem

On a live 0.2.5 host (24 threads, RTX 5070 Ti) the bundled Qwen3-4B ran on
4 threads and no GPU: ~39 tokens/s prompt, ~15 tokens/s output. The Vulkan
build exists in the spec file (`%bcond vulkan 0`) but has never been built
in CI or released, and using it is manual (`OPENVIBES_LLM_GPU_LAYERS=999`).
On the minimum host (4 cores, 8 GB, no GPU) one model call of ~750 prompt
tokens can take 30–60 s, at the edge of the default 60 s deadline.

## 2. Goals

1. After `dnf install` and `sudo openvibes-admin helper assistant-setup`, the
   assistant answers within its deadline on any supported host (floor:
   4 cores, 8 GB RAM, no GPU), with no hand-tuning.
2. A usable GPU is found and used automatically; a CPU-only host keeps
   today's strict sandbox.
3. A GPU that disappears never makes the assistant unavailable.
4. The choice is visible (one summary line, Health) and overridable.

Unchanged: the platform never downloads models from the internet (packages
come from the configured OpenVIBES repository like every other package);
no telemetry; the console's assistant API.

## 3. `openvibes-admin assistant tune`

New command, run as root through the helper; `assistant-setup` runs it.
Re-runnable at any time. Flags: `--cpu` (force CPU mode), `--no-install`
(never run dnf), `--json` (machine-readable summary).

Steps:

1. **GPU hardware**: read `/sys/bus/pci/devices/*/{class,vendor,device}`;
   display class `0x03xxxx` with vendor `0x10de` (NVIDIA), `0x1002` (AMD) or
   `0x8086` (Intel). None → CPU mode, skip 2–3.
2. **GPU build**: if `/usr/libexec/openvibes-llm/llama-server-vulkan` is
   missing, run `dnf install -y openvibes-llm-vulkan` (not with
   `--no-install`). A failed install → CPU mode, reason printed.
3. **Confirm**: run `llama-server-vulkan --list-devices` (timeout 20 s).
   Ignore software devices (name contains `llvmpipe`, `lavapipe` or
   `SwiftShader`). Choose the real device with the most memory, requiring
   model file size + 1 GiB. None → CPU mode with a named reason, e.g.
   "found GeForce RTX 5070 Ti but Vulkan reports no device: is the NVIDIA
   driver installed?".
4. **Write** `/var/lib/openvibes-llm/tuning.conf` (0644 root), read by the
   unit after `llm.conf` and before `model.conf`:
   - `OPENVIBES_LLM_THREADS` = physical cores − 2, clamped to 2..16
     (physical cores from `/sys/devices/system/cpu/cpu*/topology/core_cpus_list`
     deduplicated; fallback logical count / 2).
   - GPU mode: `OPENVIBES_LLM_GPU_LAYERS=999`, `OPENVIBES_LLM_GPU_DEVICE=<name>`;
     enable the GPU drop-in (§4). CPU mode: `OPENVIBES_LLM_GPU_LAYERS=0`;
     disable the drop-in.
   Values the operator set in `llm.conf` win: tune writes only keys absent
   from `llm.conf` and says which it left alone.
5. **Restart and measure** (§6), then print the summary (§7).

`openvibes-llm-check` validates the new keys like the existing ones
(device name ≤ 128 printable characters).

## 4. Packaging, sandbox, fallback

- **Release**: CI builds both llama.cpp variants from the same pin
  (`packaging/llm/llama-cpp.pin`) and publishes `openvibes-llm-vulkan` next
  to `openvibes-llm` (`%bcond vulkan` default 1 in release builds; build
  deps `glslc`, `vulkan-headers`). Smoke test in CI: `llama-server-vulkan
  --list-devices` exits 0 on a runner without a GPU.
- **Drop-in**: shipped disabled in `openvibes-llm-vulkan` and enabled by tune
  (a symlink under `/etc/systemd/system/openvibes-llm.service.d/`). It runs
  the Vulkan binary and opens only DRM render nodes and NVIDIA device nodes
  (`DeviceAllow=`, `DevicePolicy=closed`) plus `MemoryDenyWriteExecute=no`
  (drivers compile shaders at run time). CPU hosts keep the strict unit.
- **Fallback**: in GPU mode `openvibes-llm-check` runs `--list-devices`
  before every start. If the tuned device is missing it logs
  "GPU <name> not found; serving on CPU" and writes
  `/run/openvibes-llm/gpu-missing` (read by Health, which shows a warning
  with "run `openvibes-admin assistant tune`"); the service still starts
  and llama.cpp serves on CPU (it ignores `--gpu-layers` without a device).
- **Undo**: `assistant tune --cpu`, or removing `openvibes-llm-vulkan`
  (its `%preun` disables the drop-in and rewrites `tuning.conf` to CPU).

## 5. Small model

Package `openvibes-llm-model-small`: one 2B GGUF (~1.5 GB, Apache-2.0),
pinned by SHA-256 in `packaging/llm/model-small.pin`, installed into the
model store under its own alias `small-2b`; it does not change
`model.conf` on install. Candidate: Qwen3.5-2B-Instruct Q4_K_M. Released
only after `openvibes-admin assistant eval` passes the gate (assistant spec
§10) on the minimum host in `openvibes-lab`; if no 2B model passes, the
package is not released and tune uses the deadline route (§6) only.

## 6. Speed check and model choice

After restart, tune sends one fixed request shaped like a console call
(system prompt + ~750 tokens, `max_tokens` 200) to the local server with
the API key, and measures prompt tokens/s and output tokens/s from the
server's timings. Estimated call time `t = 750 / prompt_tps + 200 / output_tps`.

| Situation | Action |
|---|---|
| `t ≤ 0.5 × deadline_seconds` | keep the model |
| too slow, bundled 4B in use, CPU mode | install `openvibes-llm-model-small` (not with `--no-install`), set `model.conf` to it, restart, measure again |
| still too slow (or small model unavailable) | set `[assistant.backend] deadline_seconds` in `console.toml` to `ceil(2 × t)`, capped at 180, restart the console, warn "this host answers slowly (about N s per question)" |
| GPU mode | never switch to the small model |

An operator-chosen model (`model.conf` written by `assistant model install`
with an alias other than the bundled ones) is never replaced; tune only
reports its speed.

## 7. Output and Health

One line, printed by tune and stored in `/var/lib/openvibes-llm/tune.json`
(read by Health):

```
assistant: GPU (GeForce RTX 5070 Ti, 16 GB) · model qwen3-4b · ~0.9 s per call
assistant: CPU (2 threads) · model small-2b · ~22 s per call · deadline raised to 50 s
```

## 8. Failure behaviour

- No PCI access, dnf failure, Vulkan probe timeout, model package missing:
  tune continues in CPU mode or with the current model, prints the reason,
  exits 0 (the assistant still works); exit 1 only if the server cannot
  answer at all after the final restart.
- Measurement request fails: no model or deadline change; exit 1 with the
  backend error.
- tune never edits `llm.conf`; `console.toml` only for `deadline_seconds`.

## 9. Testing

- Unit: PCI parsing on fixture `/sys` trees (NVIDIA, AMD, Intel, none,
  virtio-gpu); `--list-devices` parsing (real GPU, lavapipe only, error
  output); thread formula; decision table §6; `tuning.conf` merge rules.
- Admin integration: tune against a fake `llama-server` script and a fake
  `dnf` on `PATH` (no network, no root needed with `--root DIR` test flag).
- Packaging (Fedora job): both RPMs build; drop-in enable/disable; check
  script fallback with the device missing.
- Lab (`openvibes-lab`): minimum host (CPU, small model, eval gate) and a
  GPU host (answer time).

## 10. Delivery

1. PR 1: `assistant tune` with CPU threads, `tuning.conf`, speed check,
   deadline route, summary/Health.
2. PR 2: GPU detection, Vulkan package in CI and release, drop-in,
   check-script fallback.
3. PR 3: small model package (after the lab eval passes) and switching.
