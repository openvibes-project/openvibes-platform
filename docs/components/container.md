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

Not yet here: ARM and the published image (#605), the backup before an
update (#609), the assistant (its own optional container, #643; off until
then, decision #644).

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
    date.
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

- **Volumes:** `/etc/openvibes`, `/var/lib/pgsql` and
  `/var/lib/openvibes-{admin,console,feed,ingest,llm,signer,vulns}`.
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

## Failure behaviour

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
4. a CA from your own PKI (a root and intermediate made apart, mounted as
   `OPENVIBES_CA_FILE`) is imported on a fresh first start, and the
   platform trusts that root, not one of its own.

`KEEP=1` leaves the container and its volumes for a look afterwards.
