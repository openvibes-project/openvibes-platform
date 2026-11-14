# container image

The platform as one container image (decision #602, #604): every platform
service and PostgreSQL 17, run by systemd as on the appliance, on the
appliance's base (AlmaLinux 10) with the same internal RPMs (#631). The
units, Setup, the TUI and `openvibes-admin` are the same code as on the
appliance; there's no container mode.

Not yet here: setup in the browser (#607), SSH into the TUI (#608), ARM and
the published image (#605), the backup before an update (#609). Until #607,
Setup runs inside the container: `docker compose exec openvibes
openvibes-admin`.

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
- `packaging/container/openvibes-container-start.service` runs
  `openvibes-container-start` at every start, and its output goes to the
  container's log (`docker compose logs openvibes`):
  - before Setup, it says how to run Setup;
  - after, it runs `openvibes-admin setup --repair` and prints the
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

- **Volumes:** `/etc/openvibes`, `/var/lib/pgsql` and
  `/var/lib/openvibes-{admin,console,feed,ingest,llm,signer,vulns}`.
- **Ports:** 443/tcp (console), 18423/tcp (agents), 18424/tcp (rule
  distribution), 514/udp (network devices). Each is published on the same
  number on the host: the console only answers to the address it was set
  up for, so 443 published as 8443 answers *421 Misdirected Request*. For
  another port, give Setup that port (its console, agent or distribution
  port) and publish it on both sides, for example `"8443:8443"`.
- `ENGINE=docker|podman` picks the builder and the engine the test uses;
  the default is whichever is installed, Podman first.

## Running it

```sh
docker compose up -d
docker compose logs openvibes                      # says what to do next
docker compose exec openvibes openvibes-admin      # Setup, then the TUI
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

- If Repair fails at start, `openvibes-container-start.service` fails and
  the services Repair didn't reach stay off. `docker exec <container>
  journalctl -u openvibes-container-start` shows why. Running Repair again
  from the TUI is safe.
- Without the writable cgroup tree, or on a cgroup v1 host, systemd
  can't start under Docker and the container exits at once (code 255).

## How to test

`bash scripts/container-e2e.sh [IMAGE]` starts the container from
`compose.yaml` (the console on a free port of 127.0.0.1 instead of the
host's 443) and checks, with Docker or Podman, that:

1. the image boots unprivileged with no failed unit, and the log says how
   to run Setup;
2. Setup works inside it, and the console answers on the published port;
3. a new container on the same volumes keeps the CA and the database, has
   no files without an owner, starts the services by itself, and the log
   says where the console is.

`KEEP=1` leaves the container and its volumes for a look afterwards.
