# The model comes from its publisher; the platform installs offline from one kit — design

Date: 2026-10-09. Status: approved in conversation with the user (decisions.md,
2026-10-09). Target: **v0.2.6**.

## 1. Why

- **Pages is over its limit.** The website's `collect.sh` publishes every release's RPMs, and the model RPMs (Qwen3-4B, 2.5 GB in two parts) carry the platform's version. So every release re-publishes an identical 2.5 GB, and the site is already about 2.6 GB against Pages' 1 GB. Pages' bandwidth cap (about 100 GB a month, roughly 40 model downloads) could also throttle `install.sh` for everyone.
- **The platform must install air-gapped.** That includes PostgreSQL, the other Fedora dependencies and the model. The files may be downloaded in an ordinary browser, for example on Windows, and carried over.

Requirements (the user):
1. **Online:** the model comes from its publisher (Hugging Face), pinned by SHA-256. We do not host it.
2. **Offline:** one kit per release holds everything the platform needs, PostgreSQL included. The model is a second, optional download. Both are plain browser downloads.
3. **Short, clear steps** for both online and offline installs.

## 2. Online: the model is fetched at setup

- **The pin:** `packaging/llm/model.pin` stays the single pin (`LLM_MODEL_FILE`, `LLM_MODEL_URL` at an exact Hugging Face commit, `LLM_MODEL_SHA256`, `LLM_MODEL_ALIAS`, `LLM_MODEL_LICENSE_URL`). `openvibes-llm` installs it as `/usr/share/openvibes-llm/model.pin`, read-only, so the installed platform knows the model without a model package.
- **New command:** `openvibes-admin assistant model fetch`, which:
  - reads the installed pin;
  - downloads `LLM_MODEL_URL` with `curl --proto =https --tlsv1.2 --fail --location --retry 3`, with a progress line, into a temporary file under `/var/lib/openvibes-llm` (same filesystem, so no copy across disks);
  - then hands it to the existing `model install` path (SHA-256 check, read-only install, `model.conf` selection).
  - It checks free space first: about 2.6 GB for the file.
  - A wrong hash deletes the file and fails with "the downloaded file does not match the pinned SHA-256; nothing was installed".
  - Network errors name the URL and say how to install offline from a file.
- **Setup and `assistant-setup`:** both run `model fetch` when the pinned model is not installed. Setup asks first: "Download the assistant's model (2.5 GB from Hugging Face)? [Y/n]". Saying no leaves the assistant off, and says to turn it on in Setup later. `model fetch` and `model install` refuse root and run as the `openvibes-admin` user.
- **"Never while running" still holds:** only these admin commands download, and they run only when an admin asks.
- **`curl` is a dependency** of `openvibes-admin`; it is on every Fedora install.
- **Proxies:** `curl` honours `https_proxy`, which is documented.

## 3. Packaging

- **The model bytes leave the repository.** `openvibes-llm-model-part1` and `-part2` are no longer built.
- **`openvibes-llm-model` stays, version 0.2.6, with no model bytes.** It is the upgrade bridge, and it:
  - keeps owning `%ghost /var/lib/openvibes-llm/models/<LLM_MODEL_FILE>` and `%config(noreplace) /var/lib/openvibes-llm/model.conf`;
  - **why:** in 0.2.5 it owned both, and retiring it would make rpm delete the user's model and selection on upgrade;
  - carries `Obsoletes: openvibes-llm-model-part1 < 0.2.6` and `Obsoletes: openvibes-llm-model-part2 < 0.2.6`, so the empty part packages leave cleanly;
  - in `%posttrans`, if the model file is missing, prints one line: "openvibes-llm-model: the assistant's model is not installed; turn the assistant on in openvibes-admin Setup to download it (offline: see the offline install guide)".
  - `join-model` goes away.
- **`openvibes-llm`** keeps `Recommends: openvibes-llm-model = %{version}-%{release}`, now a tiny package.
- **`check-rpm.sh`** gains two tests:
  - no package contains a `.gguf` or a model part;
  - `openvibes-llm-model` owns exactly those two paths.
- **Release workflow:** stops fetching the model (`fetch-llm-model.sh` is used only by the kit's optional model test and by CI's assistant e2e) and stops uploading model RPMs.

## 4. Offline: the platform kit

**Name:** `openvibes-platform-<version>-offline-fedora<N>.tar`, one per supported Fedora release (today 44), x86_64, attached to the GitHub release. It is an uncompressed tar, because RPMs are already compressed. It is under 2 GiB; a rough guess is 150–300 MB.

**Contents** (one top-level folder, `openvibes-offline/`):
- `install`: a POSIX sh script, run as root.
- `README.txt`, with:
  - the steps;
  - the model's Hugging Face link and SHA-256;
  - the key fingerprint;
  - a note on Fedora sources.
- `openvibes.gpg`: the OpenVIBES RPM key.
- `packages/`:
  - every OpenVIBES platform RPM (signed): `openvibes-admin`, `-console`, `-ingest`, `-distribution`, `-vulns`, `-signer`, `-llm`, `-llm-model` (the bridge);
  - the `openvibes-rules-*` packages of the release's rule sets;
  - the full dependency closure from Fedora, **including PostgreSQL**, with Fedora's own signatures;
  - `repodata/` generated with `createrepo_c`.
- `SHA256SUMS` and `SHA256SUMS.asc`: every file in the kit, plus a detached signature with the OpenVIBES key.
- `LICENSES/`: the licences of the bundled Fedora packages, and where to get their sources (for GPL redistribution).

**How CI builds it** (release workflow, job `offline-kit`, in a clean `fedora:<N>` container):
1. Install the release's freshly built, signed RPMs as a local repo.
2. Run `dnf download --resolve --alldeps --destdir packages/` for the platform packages, against a **minimal Fedora base** (the container image). The closure must include everything not on a minimal Fedora Server install.
3. Run `createrepo_c packages/`, generate `SHA256SUMS`, sign it, and build the tar.
4. **A kit test runs before upload,** in a second clean container with networking disabled: run `install --check`, then a full install (§5) with `--no-setup`, and confirm every OpenVIBES unit file and `postgresql-server` are installed. The upload fails if this fails.

## 5. The kit installer (`openvibes-offline/install`)

```
sudo ./install [--model FILE] [--no-setup] [--check]
```

1. **Refuse unless the host matches.** It must be Fedora `<N>` on x86_64. On a mismatch it fails with "this kit is for Fedora N; download openvibes-platform-<v>-offline-fedora<M>.tar".
2. **Verify the kit:**
   - import `openvibes.gpg` into a temporary keyring;
   - check that its fingerprint equals the one built into the script (the same pin as `install.sh`, `710AD8AF…86DA36`);
   - verify `SHA256SUMS.asc`, then `sha256sum -c SHA256SUMS`.
   - Any failure stops the install before anything changes.
3. **Install from the kit only:**
   - `dnf --disablerepo='*' --repofrompath=openvibes-offline,<kit>/packages --enablerepo=openvibes-offline install …` with `gpgcheck` on, then `upgrade`, naming the platform packages (a newer kit upgrades what is installed);
   - the OpenVIBES key is imported for this run only;
   - Fedora's key is passed in `gpgkey` (the host's own copy);
   - **no network access is attempted.**
4. **The model:**
   - `--model FILE`, or a `*.gguf` next to the kit (one, named `LLM_MODEL_FILE`), is checked against the pinned SHA-256 and staged in `/var/lib/openvibes-offline`. Setup installs it (`model install` needs the database, which exists only after Setup).
   - With no file, it prints that the assistant can be turned on in Setup, with the link and the SHA-256.
5. **Setup:** unless `--no-setup`, start `openvibes-admin` (Setup) as after an online install. Setup installs the staged model and does not offer to download.
6. **Idempotent:** running it again with a newer kit upgrades, and is the documented offline update path.
7. **`--check`** runs steps 1–2 only.
8. **Errors** follow `install.sh`'s style: one line saying what failed and what has changed so far. dnf's log is shown only on failure.

## 6. Steps the user sees

- **Online:**
  1. `sudo sh -c "$(curl -fsSL https://openvibes-project.github.io/install.sh)"`, as in `docs/quick-setup.md` (unchanged; it opens Setup).
  2. In Setup, choose the assistant and answer **Y** to download the model.
- **Offline:**
  1. Download `openvibes-platform-<v>-offline-fedora44.tar`, and optionally the model from the Hugging Face link, in any browser.
  2. Copy both to the server, into the same folder.
  3. Run `tar xf openvibes-platform-<v>-offline-fedora44.tar && sudo ./openvibes-offline/install`.
- **Already installed, adding the assistant later:** open Setup (`sudo openvibes-admin`) and turn on the assistant.

The download page (website, owned by the release session), `docs/quick-setup.md` and `README.txt` show these steps, word for word the same.

## 7. Failure behaviour

| Failure | Behaviour |
|---|---|
| Hugging Face down or slow | `model fetch` fails, names the URL, and gives the offline file route; the platform without the assistant is unaffected |
| File changed upstream (hash mismatch) | Nothing is installed; the message says the pin no longer matches. A new pin ships in a platform release (`assistant eval` first, as `model.pin` says) |
| Not enough disk | Checked before downloading; the message gives the size needed |
| Kit corrupted or tampered with | The signature or checksum check fails before anything changes |
| Wrong Fedora version | Refused, naming the right kit |
| Upgrade from 0.2.5 with the assistant | The model and `model.conf` stay (the §3 bridge); the part packages leave; the assistant keeps answering. Covered by the lab upgrade test |

## 8. Testing

- **Unit:** `model fetch`, with the download step injectable:
  - a good file installs;
  - a wrong hash removes the temporary file;
  - low disk is refused;
  - an existing model is a no-op.
- **`check-rpm.sh`:**
  - no `.gguf` or model part in any package;
  - the bridge owns exactly its two paths;
  - `openvibes-llm` ships `model.pin`.
- **CI kit test** (§4, step 4): a network-less container installs the platform from the kit.
- **Lab upgrade test:** 0.2.5 with the assistant, upgraded to the CI build. The GGUF and `model.conf` survive, the part packages are gone, the assistant answers, `model fetch` is a no-op, and `assistant-tune` runs.
- **Lab offline test:** a fresh Fedora 44 VM with no default route installs from the kit plus the model file, then Setup completes and the assistant answers.

## 9. Out of scope

- **Agent offline bundles:** the offline-install spec for agents (`docs/specs/2026-10-09-offline-install-and-updates-design.md`) covers them.
- **Other distributions for the platform:** it is Fedora only, for now.
- **Mirroring our dnf repo:** works today with `reposync`; not documented here.
- **The website changes:** the release session owns them (collect.sh and build-repo.sh exclusion; the downloads page). This spec gives them the kit file name pattern, the model URL and SHA-256 from `model.pin`, and the steps in §6.
