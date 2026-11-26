# container image

The platform as one container image (decision #602, #604): every platform
service and PostgreSQL 17, run by systemd as on the appliance, on the
appliance's base (AlmaLinux 10) with the same internal RPMs (#631). The
units, Setup and `openvibes-admin` are the same code as on the appliance;
there's no container mode.

The container comes installed: every setting goes in the compose file, with
the administrator password in a `.env` file next to it (#635), and the first
start sets the platform up from them (#607). There's no SSH (#634) and no
TUI: the compose file and the console are how it's run.

The assistant (early beta) is its own optional container
([openvibes-assistant.md](openvibes-assistant.md), #643): off unless
`COMPOSE_PROFILES=assistant` is in `.env`. Every start of this container
makes the key the two share (on the first start) and points the console at
the assistant; the console offers it only once it has answered (#653).

Both images are built for x86_64 and arm64 (`linux/amd64`, `linux/arm64`,
#605), each natively from that architecture's EL10 RPMs. Not yet here: the
published multi-arch image (#613).

## Interfaces

- `packaging/container/Containerfile`: the image.
  - The service accounts are created with fixed IDs (groups 960 and 961,
    accounts 970 to 979) before the packages install, so a new image finds
    the files on the volumes owned by the same accounts.
  - PostgreSQL 17 comes from PGDG, as Setup picks on AlmaLinux.
  - Units for hardware, consoles and the clock are masked: the container's
    host does that.
  - `CMD /sbin/init`, `STOPSIGNAL SIGRTMIN+3`.
- `packaging/container/compose.yaml`: what `docker compose up -d` runs: the
  image, the volumes, the ports, and what systemd needs (below). It names
  the image `ghcr.io/openvibes-project/openvibes-platform:latest`, which is
  published from #605 on; `OPENVIBES_IMAGE` picks another, such as a local
  build.
- `packaging/container/example.env`: the settings to copy to `.env`.
- `packaging/container/openvibes-container-start.service` runs
  `openvibes-container-start` at every start, and its output goes to the
  container's log (`docker compose logs openvibes`):
  - on the first start, it runs `openvibes-admin setup --quick` with the
    settings below and the appliance's components (no agent), then prints
    the console's address. systemd gives its units a clean environment,
    so it reads the `OPENVIBES_*` settings from PID 1;
  - after, it saves the settings as the plan again (`helper setup-plan`,
    as the appliance's Maintenance pages do), so a changed one is applied
    (#636), then runs `openvibes-admin setup --repair` and prints the
    console's address. Which units Setup turned on is recorded in
    `/etc/systemd/system`, which belongs to the image, not a volume, so a
    new container would otherwise start with every service off. Repair
    turns them on and starts them, and brings the database schema up to
    date;
  - on the first start after a new image (#609), before Repair, it backs
    the database up and migrates it (see *Updating* below).
- `scripts/build-container-image.sh RPM_DIR [IMAGE]`: builds the image from
  a folder of EL10 RPMs (the platform's, from `build-rpm.sh` and
  `build-console-rpm.sh` on `almalinux:10`, and an `openvibes-rules-*`
  package). `IMAGE` defaults to `openvibes-platform:dev`.

## Configuration

The settings, in `.env` (copied from `example.env`) or typed straight into
`compose.yaml`. The compose file refuses to start without the two required
ones.

| Setting | Default | What it is |
|---|---|---|
| `OPENVIBES_HOSTNAME` | required | the name agents and browsers use for this host |
| `OPENVIBES_EXTRA_NAMES` | none | more names or IP addresses, comma-separated |
| `OPENVIBES_ADMIN_PASSWORD` | required | the console's first administrator, `admin`; at least 15 characters |
| `OPENVIBES_CONSOLE_PORT` | 443 | the console; also the published port |
| `OPENVIBES_INGEST_PORT` | 18423 | agents; also the published port |
| `OPENVIBES_DISTRIBUTION_PORT` | 18424 | rule distribution; also the published port |
| `OPENVIBES_CA_FILE` | none | a PEM file with a CA certificate chain and key from your PKI, mounted in the container; without it, OpenVIBES makes its own CA |

Every start applies them: change one, run `docker compose up -d` (compose
recreates the container), and Repair makes it so.

- **Names:** new server certificates with the new names.
- **Ports:** the service moves, and the published port with it. A moved
  agent port leaves agents on other hosts calling the old one until their
  install line from the console is run again; the log says so.
- **The administrator's password** is used only to make the account on the
  first start; change it in the console after that.
- **The CA** is chosen once: `OPENVIBES_CA_FILE` is read on the first start
  only.
- **A bad setting** on a later start keeps the settings from before, says
  so in the log, and the platform still starts.

- **Volumes:** `/etc/openvibes`, `/var/lib/pgsql`,
  `/var/lib/openvibes-{admin,console,feed,ingest,signer,vulns}`,
  `/var/lib/openvibes-assistant-key` and `/var/backups/openvibes` (the
  backups made before each new image).
- **Ports:** 443/tcp (console), 18423/tcp (agents), 18424/tcp (rule
  distribution), 514/udp (network devices). Each is published on the same
  number on the host: the console only answers to the address it was set
  up for, so 443 published as 8443 answers *421 Misdirected Request*. The
  port settings above set both sides.
- `ENGINE=docker|podman` picks the builder and the engine the test uses;
  the default is whichever is installed, Podman first.

## Running it

```sh
cp example.env .env && chmod 600 .env             # then fill it in
docker compose up -d
docker compose logs openvibes                      # where the console is
```

`podman compose` takes the same file.

- **A terminal** (`tty: true`): systemd writes to its console, and in a
  container without a terminal there is none, so the log would stay empty.
- **Podman** runs systemd in a container as is; nothing is privileged.
- **Docker** mounts the cgroup tree read-only in an unprivileged
  container, and systemd stops at once ("Failed to create /init.scope
  control group: Read-only file system"). So under Docker the container
  uses the host's cgroup tree, writable: `--cgroupns host -v
  /sys/fs/cgroup:/sys/fs/cgroup:rw`, plus tmpfs on `/run`, `/run/lock`
  and `/tmp`. It's still not privileged and gets no extra capabilities,
  but root in the container can change cgroup limits on the host (ruling
  on #604). It needs a cgroup v2 host (current Debian, Ubuntu and
  Proxmox, TrueNAS SCALE, Unraid 6.12 and later). Never `--privileged`.
- **Stopping** takes longer than Docker's default 10 seconds, because
  systemd stops PostgreSQL and the services in order. The compose file
  gives it 60 seconds (`stop_grace_period`); without compose, `docker stop
  -t 60`. A kill can leave PostgreSQL recovering on the next start.

## Updating

A new version is a new image: pull it and recreate the container.

```sh
docker compose pull
docker compose up -d
```

The start compares the image's version with the one recorded on the
`/etc/openvibes` volume (`container-image`). When they differ, before
Repair starts anything:

1. it backs up the database to the backups volume,
   `/var/backups/openvibes/openvibes-<old version>-<UTC date>-<time>.dump`
   with its `.roles.sql`, the same backup as Update's on the appliance;
2. it migrates the database, changes to stored data included (Repair alone
   applies only additive ones);
3. it keeps the newest three of these backups and deletes the older ones;
4. it runs Repair, which starts the services, and records the new version.

Each step is a line in the container's log. A volume set up before this
was recorded has no version, so its first new image is not backed up.

## Failure behaviour

- **A failed backup or migration on a new image** stops the start with the
  reason, and the services stay off. A failed backup has changed nothing,
  and a failed migration leaves the database as it was, so the previous
  image works on it. The log names that image:
  `OPENVIBES_IMAGE=ghcr.io/openvibes-project/openvibes-platform:<old
  version>` in `.env`, then `docker compose up -d`. The backup stays on the
  backups volume.

- A missing or invalid setting stops the first start before anything is
  set up: the log says which one and to run `docker compose up -d` again
  after fixing it, and compose recreates the container with the new value.
  If Setup itself fails part way, the next start runs Repair with the
  settings it began with.
- If Repair fails at start, `openvibes-container-start.service` fails and
  the services Repair didn't reach stay off. `docker exec <container>
  journalctl -u openvibes-container-start` shows why. Restarting the
  container (`docker compose restart`) runs Repair again, which is safe.
- Without the writable cgroup tree, or on a cgroup v1 host, systemd
  can't start under Docker and the container exits at once (code 255).

## How to test

`bash scripts/container-e2e.sh [IMAGE]` starts the container from
`compose.yaml` (the console on a free port of 127.0.0.1 instead of the
host's 443) and checks, with Docker or Podman, that:

0. compose refuses to start without `OPENVIBES_HOSTNAME`;
1. the image boots unprivileged, and a password that's too short stops the
   first start with a message, with nothing set up;
2. with the password fixed, `compose up -d` sets the platform up, the log
   says where the console is, `admin` signs in with the password, and the
   console answers on the published port;
3. a new container on the same volumes keeps the CA and the database, has
   no files without an owner, starts the services by itself, and the log
   says where the console is; with a name added and the ingest port moved
   meanwhile, the console's certificate has the new name, ingest listens on
   the new port, and the log says agents still call the old one.
3a. on x86_64 (agent packages are x86_64 only), an agent on "another
   host" (a systemd container on the host's network, reaching the
   published agent ports on 127.0.0.1) is installed from the project's
   website with the line `openvibes-admin agent command` prints, the
   console's *Copy CLI install*; it enrolls, fetches its rules and reports
   a scan;
3b. a new image (simulated: the recorded version is set to an older one)
   backs the database up to the backups volume as a readable dump with
   its roles file, migrates it, keeps the newest three such backups
   (deleting an older one's roles file too), records the new version, and
   the platform comes back; the agent from 3a stays enrolled and the
   platform hears from it again;
4. a CA from your own PKI (a root and intermediate made apart, mounted as
   `OPENVIBES_CA_FILE`) is imported on a fresh first start, and the
   platform trusts that root, not one of its own.

`KEEP=1` leaves the containers and their volumes for a look afterwards.
Step 3a needs the internet (the install line fetches from the website) and
the host's ports 18423, 18424 and 18500 on 127.0.0.1.

CI runs this on an x86_64 and an arm64 runner (#605), each with images
built from that architecture's RPMs.
