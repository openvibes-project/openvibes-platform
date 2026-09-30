# Releases, package repository and install script — design

Status: approved by the user in conversation, 2026-09-27; written spec
awaiting review. Sub-project 1 of the easy setup (workspace `decisions.md`,
"Easy setup" and "Releases and install script"). The admin TUI spec
(`2026-09-27-admin-tui-design.md` §6.1) relies on it.

## 1. Decisions (the user, 2026-09-27)

- **Where:** a new public repository `openvibes-project/openvibes-project.github.io`
  (the organisation's Pages site). It holds only the install script, the
  public signing key, the dnf repository file and the publishing workflow.
  Script: `https://openvibes-project.github.io/install.sh`; packages:
  `https://openvibes-project.github.io/rpm/fedora/44/x86_64/`. A custom
  domain can be added on top later without changing anything else.
- **Signing key:** a dedicated OpenVIBES package key, kept only as GitHub
  organisation secrets for the release workflows (plus an offline copy the
  user keeps for replacement). Releases are fully automatic from a tag.
- **Agent CA:** the agent command carries the root certificate's SHA-256
  fingerprint; the script fetches the certificate from a new public ingest
  endpoint `GET /v1/ca` and installs it only if the fingerprint matches.
- **Releases:** independent per repository (`openvibes-platform`,
  `openvibes-agent`), tag `vX.Y.Z` by an admin. The package repository keeps
  every released version of both. No testing channel for now.
  **Agent and platform share the version:** bump and tag both on every
  release, even if one didn't change. The console marks agents older than
  the platform's version as outdated (board #54), so a platform-only
  release would mark the whole fleet outdated for an agent that doesn't
  exist.
- **Hosts:** Fedora 44 on x86_64 only; the script refuses anything else.

## 2. Release workflow (`openvibes-platform`, `openvibes-agent`)

`.github/workflows/release.yml`, on a pushed tag `v*`:

1. The tag must equal `v` + the workspace `Cargo.toml` version, else fail.
2. Build the RPMs as CI's Fedora job does, in `fedora:44` (the platform:
   `openvibes-{ingest,distribution,vulns,admin,llm}` and the console RPM;
   the agent: `openvibes-agent`). No `debuginfo` packages are published.
3. Sign them: import `RPM_SIGNING_KEY` into a temporary `GNUPGHOME`,
   `rpmsign --addsign` with `%_gpg_name` set to the key's fingerprint and the
   passphrase from `RPM_SIGNING_PASSPHRASE` (never echoed, `::add-mask::`).
   The temporary keyring is deleted in an `always()` step.
4. Check every package: `rpm --import` the committed public key into a
   clean rpm database, then `rpm -K` must report the signature as OK for
   each file. A failure stops the job; nothing is released.
5. Create the GitHub Release for the tag (as a draft first, published only
   after step 4) with the signed RPMs and `SHA256SUMS`.
6. Dispatch `publish` to the Pages repository (`repository_dispatch`, event
   `release-published`) with `PAGES_DISPATCH_TOKEN`.

The committed public key lives in each code repository at
`packaging/rpm/openvibes-packages.gpg` (the same file as the Pages
repository's `openvibes.gpg`), so step 4 needs no network. Only admins
create tags (existing rule); the secrets are limited to these two
repositories.

## 3. Pages repository

Contents:

| Path | What |
|---|---|
| `install.sh` | §4; the key's fingerprint written into it |
| `openvibes.gpg` | ASCII-armoured public key |
| `openvibes.repo` | `baseurl=https://openvibes-project.github.io/rpm/fedora/$releasever/$basearch/`, `gpgcheck=1`, `repo_gpgcheck=1`, `gpgkey=https://openvibes-project.github.io/openvibes.gpg`, `enabled=1` |
| `.github/workflows/publish.yml` | below |
| `tests/` | the container test (§6) |
| `README.md` | what this is, how to verify the key, key replacement |

`publish.yml`, on `repository_dispatch` (`release-published`), on
`workflow_dispatch`, and on pushes to `main`:

1. Download the RPM assets of every published (non-draft) release of
   `openvibes-platform` and `openvibes-agent` (`gh release download`).
2. Check each with `rpm -K` against `openvibes.gpg`; any failure stops the
   job, so the live site keeps its previous state (nothing is silently
   left out).
3. `createrepo_c` into `site/rpm/fedora/44/x86_64/`; sign `repomd.xml` with
   the same key (`gpg --detach-sign --armor` → `repomd.xml.asc`), using the
   same secrets, which are also granted to this repository.
4. Copy `install.sh`, `openvibes.gpg`, `openvibes.repo`, `README.md` (as
   `index.html` via a minimal page) into `site/` and deploy with
   `actions/upload-pages-artifact` and `actions/deploy-pages`.

The site is rebuilt from the releases each time; no package ever lives in
git. Every action is pinned to a commit SHA, as in the other repositories.

## 4. `install.sh`

POSIX `sh`, readable in one sitting. Run as
`curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh` (the
platform) or `… | sudo sh -s -- --agent --platform HOST[:PORT] --token T
--ca-sha256 FP` (an agent). Documented safer form: download, read, then
`sudo sh install.sh …`. It stops at the first failure and says what it did
so far (e.g. "repository added, nothing installed").

Both modes:

1. Refuse unless root; refuse unless `/etc/os-release` says `ID=fedora`,
   `VERSION_ID=44`, and `uname -m` is `x86_64`.
2. Repository: download `openvibes.gpg` to a temp file, compare its
   fingerprint (`gpg --show-keys --with-colons`) with the one in the
   script; on a mismatch stop with nothing changed. `rpm --import` it and
   write `/etc/yum.repos.d/openvibes.repo`. If both are already present
   and identical, leave them; if they differ, stop and say so.

Platform mode (default):

3. `dnf install -y openvibes-admin`.
4. With a terminal on `/dev/tty` and a `SUDO_USER`: run `openvibes-admin`
   as that user with `/dev/tty` as its input and output (the Setup tab
   opens on a new host). Otherwise print the next steps, including the
   `setup --quick` form.

Agent mode (`--agent`):

3. Check arguments: HOST a DNS name or IP address with an optional port
   (default 18423); T 43 characters of base64url; FP 64 hexadecimal digits,
   colons allowed. Refuse if `/etc/openvibes-agent/agent.toml` already has a
   `platform_url` other than the packaged example (say how to re-enroll).
4. CA: `curl --insecure https://HOST:PORT/v1/ca` into a temp file; compute
   the SHA-256 of its DER form (as Setup's fingerprint is), with coreutils
   only: the PEM body without its header lines, `base64 -d | sha256sum`;
   stop unless it equals FP. Then `curl --cacert` that file to the same URL, which must
   succeed: the server's certificate chains to that root.
5. `dnf install -y openvibes-agent`.
6. Write `platform-ca.crt` (0644), `token` (0600 `openvibes_agent`) and
   `agent.toml` (0640 `root:openvibes_agent`: `platform_url =
   "https://HOST[:PORT]"`, the packaged paths), as Setup's agent step does;
   `systemctl enable --now openvibes-agent`.
7. Wait up to 60 seconds for the agent's journal line `enrolled as
   AGENT_ID` (`journalctl -u openvibes-agent`), then print "enrolled" and
   the id, or where to look.

The token appears in the process list while the one-line command runs; it
is single-use or short-lived (Setup's endpoint token: 24 hours, 10 uses),
and the TUI says so next to the command.

## 5. `GET /v1/ca` and the agent command

- **Protocol first:** `openvibes-protocol` adds `GET /v1/ca`: no client
  certificate, no body; `200` with `Content-Type:
  application/x-pem-file` and the platform's root certificate (PEM, one
  certificate). Public data; the fingerprint in the agent command is the
  trust anchor.
- **Ingest:** serves it from `/etc/openvibes/pki/root.crt` (read at start,
  like the other TLS material; `503` if missing), on the existing TLS
  listener, rate-limited like `/v1/enroll`.
- **Setup:** the last screen (admin TUI spec §6.3 step 13) shows
  `curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s --
  --agent --platform HOSTNAME --token TOKEN --ca-sha256 FINGERPRINT`,
  and `openvibes-admin` gains `agent command` (prints the same line with a
  new 24-hour, 10-use token) so it can be copied without the TUI's
  wrapping.

## 6. Testing

- `shellcheck install.sh` in the Pages repository's CI.
- Container test (Pages repository, run in CI and locally): builds RPMs
  from both code repositories' `main`, signs them with a throwaway key,
  serves a `createrepo_c` repository over local HTTP, and runs
  `install.sh` pointed at it (`OPENVIBES_REPO_URL` and
  `OPENVIBES_KEY_FINGERPRINT` overrides, honoured only when set, for this
  test):
  - platform mode in one systemd container: `openvibes-admin` installed,
    `setup --quick` completes, `openvibes-admin agent command` prints the
    line;
  - agent mode in a second container on the same network with that line:
    the agent enrolls;
  - refusals: wrong key fingerprint (nothing installed), wrong CA
    fingerprint (no agent package), non-Fedora image, already configured
    agent.
- Release workflows: `rpm -K` on every package before the release is
  published (§2 step 4); a dry run on a fork with a throwaway key before
  the first real tag.
- Ingest: HTTP test for `/v1/ca` (PEM body equals the file; no client
  certificate needed; `503` when missing).

## 7. One-time setup (the user, with exact commands in the plan)

1. Generate the key: `gpg --quick-gen-key "OpenVIBES packages
   <26064407+itismelime@users.noreply.github.com>" rsa4096 sign 3y`.
2. Export it (`gpg --armor --export-secret-keys FPR`) into the organisation
   secret `RPM_SIGNING_KEY` and its passphrase into `RPM_SIGNING_PASSPHRASE`,
   both limited to `openvibes-platform`, `openvibes-agent` and the Pages
   repository. Export the public key into the repositories (§2, §3).
3. Keep an offline copy of the secret key (USB stick) for replacement and
   revocation; delete it from the machine.
4. A fine-grained token able only to dispatch workflows on the Pages
   repository → secret `PAGES_DISPATCH_TOKEN` in the two code repositories.
5. Create the Pages repository with the same branch protection as the
   others and Pages source "GitHub Actions".

Key replacement (in the Pages README): publish the new public key next to
the old in `openvibes.gpg`, re-sign and re-publish, update the fingerprint
in `install.sh`, then remove the old key.

## 8. Failure behaviour

- A release whose signing or check fails stays a draft; nothing is
  published.
- `publish.yml` refuses to publish if any package fails the check; the
  previous site stays live.
- `install.sh` stops at the first failure, says what was done, and never
  overwrites an existing agent configuration or repository file that
  differs.
- `/v1/ca` without a root certificate on disk answers `503`; the script
  reports "the platform has no CA yet: finish Setup first".

## 9. Delivery

One PR each, in order:

1. Protocol: `GET /v1/ca` (contract, fixture).
2. Platform: ingest `/v1/ca`; `openvibes-admin agent command`; Setup's
   last screen; `release.yml`; `packaging/rpm/openvibes-packages.gpg`.
3. Agent: `release.yml`; the same public key file; one journal line
   `enrolled as AGENT_ID` when enrollment succeeds (the script waits for it).
4. Pages repository: `install.sh`, `openvibes.gpg`, `openvibes.repo`,
   `publish.yml`, README, the container test.
5. First release: the user tags `v0.1.0` on both code repositories; we
   watch it publish, then run the one-line install on a fresh Fedora 44
   host together.

The quick-setup guide (sub-project 4) follows as a page in the Pages
repository.
