# Assistant tune 2: GPU detection, Vulkan package, fallback — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** `assistant tune` finds a usable GPU, installs and switches to the Vulkan build, and falls back to CPU without an outage when the GPU disappears; the release ships `openvibes-llm-vulkan`.

**Architecture:** Pure parsers (PCI display devices, `--list-devices` output) and a device choice in `tune.rs`; `tune_run.rs` gains the GPU path (dnf install, probe, drop-in enable/disable); the RPM builds the Vulkan variant by default and ships a disabled drop-in; `openvibes-llm-check` re-probes in GPU mode before every start and writes a marker Health reads.

**Tech Stack:** Rust, RPM spec, systemd drop-ins, llama.cpp Vulkan build, GitHub Actions.

**Spec:** `docs/superpowers/specs/2026-10-07-assistant-tune-design.md` §3 steps 1–4, §4, §7, §8. **Depends on:** plan 1 merged (`tune.rs`, `tune_run.rs`, `tuning.conf`, helper command).

## Global Constraints

- PCI: `/sys/bus/pci/devices/*/class` starting `0x03`, vendor `0x10de` NVIDIA / `0x1002` AMD / `0x8086` Intel. Anything else (virtio, ASPEED, Matrox) is "no GPU".
- Software Vulkan devices ignored: name contains `llvmpipe`, `lavapipe` or `SwiftShader` (case-insensitive).
- Device needs memory ≥ model file size + 1 GiB; choose the largest.
- New closed-set runner programs: `Program::LlamaVulkan` → `/usr/libexec/openvibes-llm/llama-server-vulkan` (only `--list-devices`, 20 s timeout). dnf goes through the existing `Program::Dnf` (`install -y openvibes-llm-vulkan`), skipped with `--no-install`.
- Drop-in path: `/etc/systemd/system/openvibes-llm.service.d/50-vulkan.conf` → symlink to `/usr/lib/openvibes-llm/vulkan.conf` (shipped by the package); tune creates/removes the symlink, then `systemctl daemon-reload`.
- Drop-in content: `ExecStart=` reset and the same command with `llama-server-vulkan`; `PrivateDevices=no`, `DevicePolicy=closed`, `DeviceAllow=/dev/dri/renderD* rw` plus `char-drm rw` and NVIDIA nodes (`/dev/nvidia0`, `/dev/nvidiactl`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools` rw); `MemoryDenyWriteExecute=no`; `ExecPaths=` unchanged plus the driver library dirs llama needs (verify on this host: RTX 5070 Ti, NVIDIA 615.71).
- `tuning.conf` in GPU mode: `OPENVIBES_LLM_GPU_LAYERS=999`, `OPENVIBES_LLM_GPU_DEVICE=<name>`; the check script must accept `OPENVIBES_LLM_GPU_DEVICE` (≤ 128 printable chars).
- Fallback marker: `/run/openvibes-llm/gpu-missing` (RuntimeDirectory) containing the device name; Health warns "GPU <name> not found; serving on CPU — run `sudo openvibes-admin helper assistant-tune`".
- `%preun` of `openvibes-llm-vulkan` on erase: remove the drop-in symlink, rewrite `tuning.conf` GPU keys to CPU (`GPU_LAYERS=0`, drop `GPU_DEVICE`), `daemon-reload`, `try-restart openvibes-llm`.
- Summary line GPU form: `assistant: GPU (<name>, <GiB> GB) · model <alias> · ~<t> s per call`.
- Gate: `testing.md` §2 and §3; the Vulkan build needs `glslc` and `vulkan-headers` in the Fedora job.

## Review Focus

1. A host whose only Vulkan device is lavapipe stays on CPU with the strict sandbox (Task 1 + Task 3 tests).
2. NVIDIA card present but driver missing: tune names the driver in its reason and stays on CPU (Task 1 parser test on the real error text).
3. GPU removed after tuning: service starts on CPU, marker written, Health warns (Task 4 test).
4. `dnf` offline: tune stays CPU and exits 0 (Task 3 test).
5. Removing `openvibes-llm-vulkan` leaves a working CPU service (Task 5 Fedora check).

---

### Task 1: Parsers and device choice (pure, in `tune.rs`)

**Produces:**
```rust
pub enum Vendor { Nvidia, Amd, Intel }
pub fn gpus_from_pci(entries: &[(String /*class*/, String /*vendor*/)]) -> Vec<Vendor>;
pub struct VkDevice { pub name: String, pub memory_mib: u64 }
pub fn parse_list_devices(stdout: &str) -> Vec<VkDevice>;   // real devices only
pub fn choose(devices: &[VkDevice], model_bytes: u64) -> Option<&VkDevice>;
pub fn gpu_reason(found: &[Vendor], devices: &[VkDevice], probe_error: Option<&str>) -> String;
```
- [ ] **Step 1:** Capture real `--list-devices` output on this host once the Vulkan build exists (Task 2 builds it; until then use llama.cpp's documented format from the pinned source `common/arg.cpp` / `--list-devices` printer) and store fixtures under `crates/openvibes-admin/tests/fixtures/vulkan/`: `nvidia.txt`, `lavapipe-only.txt`, `nvidia-plus-lavapipe.txt`, `no-driver.txt` (stderr when the ICD fails). Write tests: NVIDIA parsed with memory; lavapipe filtered; choose picks largest ≥ model+1 GiB; none → `gpu_reason` mentions "NVIDIA driver" when vendor is NVIDIA and no device; `gpus_from_pci` on fixture pairs (NVIDIA 0x030000/0x10de → Nvidia; virtio 0x030000/0x1af4 → none; 0x020000 NIC → none).
- [ ] **Step 2:** FAIL. **Step 3:** implement. **Step 4:** PASS. **Step 5:** commit `"Admin: GPU parsers for assistant tune"`.

### Task 2: Build and ship the Vulkan package

**Files:** `packaging/rpm/openvibes-platform.spec` (`%bcond vulkan 1`; `BuildRequires: glslc vulkan-headers vulkan-loader-devel` under the bcond; install `llama-server-vulkan`, `/usr/lib/openvibes-llm/vulkan.conf`; `%preun -n openvibes-llm-vulkan` per Global Constraints), create `packaging/llm/vulkan.conf`, `scripts/build-rpm.sh` (build both variants via `scripts/build-llama-server.sh cpu|vulkan`), `.github/workflows/ci.yml` and `release.yml` (install the build deps; cache key per variant; smoke step `target/llama/vulkan/llama-server --list-devices` exits 0), `docs/components/openvibes-llm.md`.
- [ ] **Step 1:** Build locally in the Fedora container (`testing.md` §3) and run the smoke command; on this host run the built binary's `--list-devices` and save the real output as the Task 1 fixture `nvidia.txt` (replace any placeholder fixture with it).
- [ ] **Step 2:** `rpm -qlp` the vulkan RPM: binary, drop-in source, no files outside `/usr`. `rpmlint` clean of new errors.
- [ ] **Step 3:** Commit `"RPM: build and ship openvibes-llm-vulkan"`.

### Task 3: GPU path in `tune_run.rs`

Flow inserted before the thread plan: PCI scan → if GPU vendor found and not `--cpu`: ensure package (dnf unless `--no-install`) → `Program::LlamaVulkan --list-devices` → `choose` → GPU mode writes `GPU_LAYERS=999` + `GPU_DEVICE` (respecting the operator-set rule for GPU_LAYERS) and enables the drop-in; otherwise CPU mode, drop-in removed, reason printed. `--cpu` forces CPU and removes the drop-in.
- [ ] **Step 1: Failing tests** in `tests/assistant_tune.rs` with the `--root` tree from plan 1 plus `sys/bus/pci/devices/0000:09:00.0/{class,vendor}` and injected runner fakes (dnf ok/fail, list-devices fixture or error): NVIDIA + device → GPU mode, symlink created, summary "GPU (…)"; lavapipe only → CPU, no symlink; dnf fails → CPU, exit 0, reason; `--cpu` after GPU → symlink removed, `GPU_LAYERS=0`.
- [ ] **Step 2–4:** FAIL → implement (extend the runner trait from plan 1 with `list_devices()` and `install_vulkan()`) → PASS. **Step 5:** commit `"Admin: assistant tune uses the GPU"`.

### Task 4: Check-script fallback and Health

**Files:** `crates/openvibes-llm/src/{lib.rs,main.rs}` (accept `OPENVIBES_LLM_GPU_DEVICE`; when `GPU_LAYERS > 0` and the device is set, run `llama-server-vulkan --list-devices` (timeout 20 s) and if the device is absent: log the warning, write the marker, exit 0; else remove the marker), `packaging/rpm/openvibes-llm.service` (`RuntimeDirectory=openvibes-llm` if not present), TUI Health check reading the marker.
- [ ] **Step 1: Failing tests:** lib unit test with an injected device list (present → no marker; absent → marker text). **Step 2–4:** FAIL → implement → PASS. **Step 5:** commit `"LLM check: fall back to CPU when the GPU is gone"`.

### Task 5: Docs, gate, real-host check

- [ ] Docs: `openvibes-llm.md` (GPU section rewritten: automatic, sandbox delta, fallback, undo), `openvibes-admin.md` (tune flags), `console-assistant.md` (one line: setup tunes CPU/GPU).
- [ ] Gate §2 + §3 (Fedora job incl. install/erase of the vulkan RPM: after erase, `systemctl start openvibes-llm` works on CPU).
- [ ] On this host with the CI RPMs: `sudo openvibes-admin helper assistant-tune` → GPU summary naming the RTX 5070 Ti; ask the dock one question; record seconds per call in the PR body. Open the PR.
