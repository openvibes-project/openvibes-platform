# offline kit

The platform installed on a server with no network access: one tar per release
and Fedora version, `openvibes-platform-<version>-offline-fedora<N>.tar` (today
44, x86_64). Spec: `docs/superpowers/specs/2026-10-09-model-download-and-offline-kit-design.md`
§4, §5. The user steps are the three in that spec's §6 (download, copy, run
`tar xf … && sudo ./openvibes-offline/install`).

## Contents (`openvibes-offline/`)

| Path | What |
|---|---|
| `install` | the POSIX sh installer (`packaging/offline/install`, version and Fedora number filled in at build time) |
| `README.txt` | the steps, the model's link, SHA-256 and licence, the key fingerprint, a note on Fedora sources (`packaging/offline/README.txt.in`) |
| `openvibes.gpg` | the OpenVIBES package key (`packaging/rpm/openvibes-packages.gpg`) |
| `packages/` | the signed OpenVIBES packages (admin, console, ingest, distribution, vulns, signer, llm, llm-model), the `openvibes-rules-*` packages, `postgresql-server`, and every Fedora package they need that a minimal fedora image lacks; `repodata/` from `createrepo_c` |
| `SHA256SUMS`, `SHA256SUMS.asc` | every file in the kit; a detached signature by the package key |
| `LICENSES/fedora-packages.txt` | name, licence, source RPM and `https://src.fedoraproject.org/rpms/<source>` of each bundled Fedora package (GPL source offer) |

The model is not in the kit (2.5 GB, a Hugging Face link in `README.txt`).
Typical size: about 55 MB.

## Building

`scripts/build-offline-kit.sh RPM_DIR OUT_DIR FEDORA` runs as root in a clean
`fedora:<N>` container with network access and the checkout mounted. It takes
the package list of the image first (the "base"), builds a local repository of
the OpenVIBES packages, runs `dnf download --resolve --alldeps` for them and
`postgresql-server`, drops every non-OpenVIBES package whose name the base has,
runs `createrepo_c`, and writes `README.txt`, `LICENSES/` and `SHA256SUMS`.
Signing is the caller's job: put `SHA256SUMS.asc` into `OUT_DIR/openvibes-offline/`
and run `build-offline-kit.sh --pack OUT_DIR FEDORA` to write the tar. The
release workflow's `offline-kit` job does this after the `release` job
(packages from the release, rule sets from the latest `openvibes-rules`
release, checksums signed with the same key as the RPMs), tests the tar, and
uploads it only if the test passed.

## The installer

`install [--model FILE] [--no-setup] [--check]`, as root (`--check` needs no
root):

1. The host must be Fedora `<N>` on x86_64, else it names the right kit.
2. The kit is verified: `openvibes.gpg` must be the key with the built-in
   fingerprint (`KEY_FINGERPRINT`), `SHA256SUMS.asc` must be signed by it,
   every file must match `SHA256SUMS`, and nothing else may be in the kit. A
   temporary `GNUPGHOME` is used. `--check` stops here. Test hook:
   `OPENVIBES_KEY_FINGERPRINT` replaces the fingerprint (as in `install.sh`).
3. `dnf` installs the packages from the kit's repository only
   (`--disablerepo='*'`, `gpgcheck=1`, the OpenVIBES key imported from a copy
   made after step 2; it stays in the rpm database, as with an online install).
4. The model: `--model FILE` or `<kit>/../<LLM_MODEL_FILE>` goes to
   `openvibes-admin assistant model install FILE --sha256 <pin>` (pin read from
   `/usr/share/openvibes-llm/model.pin`). That command refuses root, so the
   file must be readable by `openvibes-admin`; if it is not (a file under
   `/root`), the installer copies it into a fresh `/var/tmp/openvibes-model.*`
   (mode 0755 directory, 0444 file, group `openvibes-admin`, free space checked
   first) and removes the copy on every exit. The original is never changed.
   With no file it says the assistant can be turned on in Setup, or the model
   added later (link and SHA-256).
5. Unless `--no-setup`, and when a person ran it under sudo on a terminal,
   Setup opens.

Errors are one line, `openvibes offline install: <what failed> (<what has
changed so far>)`; dnf's log is shown only on failure. Running it again with a
newer kit upgrades (the update path for an offline host).

## Failure behaviour

| Failure | Result |
|---|---|
| Other Fedora version or architecture | refused, naming `openvibes-platform-<v>-offline-fedora<M>.tar`; nothing changed |
| Altered key, signature, checksum, extra or special files | refused before anything changes |
| dnf cannot install | dnf's last lines and "nothing changed" or what did |
| Model step fails (wrong file, admin error) | the packages stay installed; the message says the model is not |

## Testing

- `scripts/offline-kit-test-kit.sh RPM_DIR OUT_DIR 44` builds a kit signed with
  a throwaway key (re-signing the RPMs with it; needs podman and network) and
  writes the key's fingerprint to `OUT_DIR/fingerprint`.
- `OPENVIBES_KEY_FINGERPRINT=$(cat OUT_DIR/fingerprint) scripts/offline-kit-e2e.sh KIT_TAR`
  runs the checks with `--network none` containers: a tampered `SHA256SUMS`, a
  tampered package and an extra file each fail `--check`; a `fedora:43`
  container refuses with the kit's name; in a `fedora:44` container `--check`
  passes, a wrong `--model` file fails at the model step with the packages
  installed, a second install succeeds, and every OpenVIBES package,
  `postgresql-server`, a rule set and `model.pin` are present.
- CI runs the same on pull requests that touch `packaging/offline/`,
  `scripts/*offline*` or the spec (job `offline-kit`), with the PR's unsigned
  RPMs; the release job runs it with the real key before uploading.
- Not covered yet: a successful model install (`assistant
  model install` needs the database, which does not exist before Setup).
