### Task 1: Packaging — the model leaves; a bridge stays

**Files:**
- Modify: `packaging/rpm/openvibes-platform.spec` (model packages ~lines 127-160, `%install` ~225-241, `%files` ~424-445), `scripts/build-rpm.sh` (~lines 2-25), `scripts/check-rpm.sh`, `docs/components/openvibes-llm.md` (~232-262), `.github/workflows/release.yml` (only if it sets `OV_LLM_MODEL`; otherwise nothing)
- Delete: `packaging/llm/join-model.sh` (only if nothing else references it — grep)

**Interfaces:**
- Produces:
  - `/usr/share/openvibes-llm/model.pin`, installed 0644 by `openvibes-llm`;
  - the bridge `openvibes-llm-model-%{version}`, which:
    - owns `%ghost %attr(0444, root, root) %{_sharedstatedir}/openvibes-llm/models/$LLM_MODEL_FILE` and `%config(noreplace) %attr(0644, root, root) %{_sharedstatedir}/openvibes-llm/model.conf` (the same content as 0.2.5: it selects `LLM_MODEL_FILE` with `LLM_MODEL_ALIAS`);
    - declares `Obsoletes: openvibes-llm-model-part1 < %{version}-%{release}` and `Obsoletes: openvibes-llm-model-part2 < %{version}-%{release}`;
    - `Requires: openvibes-llm = %{version}-%{release}`.

- [ ] **Step 1: Write the failing checks** in `scripts/check-rpm.sh`, after the build:
  - no RPM in `target/rpm/RPMS` contains a `*.gguf`, `*.part0` or `*.part1` (`rpm -qlp`);
  - there is no `openvibes-llm-model-part*` RPM;
  - `rpm -qlp` of `openvibes-llm-model-*.rpm` lists exactly the two paths above, plus its licence file and `%dir`s;
  - `rpm -qp --obsoletes` lists both part packages;
  - `openvibes-llm` lists `/usr/share/openvibes-llm/model.pin`.
- [ ] **Step 2:** Run `bash scripts/build-rpm.sh && bash scripts/check-rpm.sh`. It fails, because today's build has parts unless `OV_LLM_MODEL=0`. Note: building with the model downloads 2.5 GB, so run Step 2 with the current default only if the model is already cached in `target/`; otherwise run it with `OV_LLM_MODEL=0` and expect the ownership and pin checks to fail.
- [ ] **Step 3: Implement.**
  - **Spec:**
    - remove `%bcond model` and both part packages;
    - the bridge package has no `%if %{with model}`;
    - `%install` writes `model.conf` from the pin as today, plus the `%ghost` list line;
    - remove `join-model` and its `%posttrans`;
    - add the bridge's `%posttrans`:
      ```sh
      [ -e %{_sharedstatedir}/openvibes-llm/models/$LLM_MODEL_FILE ] || echo "openvibes-llm-model: the assistant's model is not installed: run 'sudo openvibes-admin assistant model fetch', or install it from a file (docs: offline install)" >&2
      ```
      The file name is substituted at build time from the pin.
    - `openvibes-llm` installs `packaging/llm/model.pin` to `%{_datadir}/openvibes-llm/model.pin`.
  - **`build-rpm.sh`:** drop `fetch-llm-model.sh` and `OV_LLM_MODEL`, and update the header comment.
  - **`docs/components/openvibes-llm.md`:** describe the bridge, `model fetch`, and why the model is no longer packaged.
- [ ] **Step 4:** Run `bash scripts/build-rpm.sh && bash scripts/check-rpm.sh` (it must pass) and `bash scripts/check-names.sh`. Run the systemd e2e (`scripts/systemd-e2e.sh`) only if it is under 15 min locally; otherwise rely on CI and say so.
- [ ] **Step 5: Commit:** "Packaging: the model leaves the packages; openvibes-llm-model keeps owning the model path across upgrades".

