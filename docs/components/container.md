# container image

The platform as one container image (decision #602, #604): every platform
service and PostgreSQL 17, run by systemd as on the appliance, on the
appliance's base (AlmaLinux 10) with the same internal RPMs (#631). The
units, Setup, the TUI and `openvibes-admin` are the same code as on the
appliance; there's no container mode.

Not yet here: the compose file (#606), setup in the browser (#607), SSH into
the TUI (#608), ARM and the CI build (#605), the backup before an update
(#609). Until #607, Setup runs inside the container:
`docker exec -it <container> openvibes-admin`.

## Interfaces

- `packaging/container/Containerfile`: the image.
  - The service accounts are created with fixed IDs (groups 960 and 961,
    accounts 970 to 979) before the packages install, so a new image finds
    the files on the volumes owned by the same accounts.
  - PostgreSQL 17 comes from PGDG, as Setup picks on AlmaLinux.
  - Units for hardware, consoles and the clock are masked: the container's
    host does that.
  - `CMD /sbin/init`, `STOPSIGNAL SIGRTMIN+3`.
- `packaging/container/openvibes-container-start.service`: at every start,
  if Setup has run (`/etc/openvibes/setup.toml` exists), runs
  `openvibes-admin setup --repair`. Which units Setup turned on is recorded
  in `/etc/systemd/system`, which belongs to the image, not a volume, so a
  new container would otherwise start with every service off. Repair turns
  them on and starts them, and brings the database schema up to date.
- `scripts/build-container-image.sh RPM_DIR [IMAGE]`: builds the image from
  a folder of EL10 RPMs (the platform's, from `build-rpm.sh` and
  `build-console-rpm.sh` on `almalinux:10`, and an `openvibes-rules-*`
  package). `IMAGE` defaults to `openvibes-platform:dev`.

## Configuration

- **Volumes:** `/etc/openvibes`, `/var/lib/pgsql` and
  `/var/lib/openvibes-{admin,console,feed,ingest,llm,signer,vulns}`.
- **Ports:** 443/tcp (console), 18423/tcp (agents), 18424/tcp (rule
  distribution), 514/udp (network devices).
- `ENGINE=docker|podman` picks the builder and the engine the test uses;
  the default is whichever is installed, Podman first.

## Running it

- **Podman** runs systemd in a container as is; nothing is privileged.
- **Docker** needs a cgroup v2 host (current Debian, Ubuntu and Proxmox,
  TrueNAS SCALE, Unraid 6.12 and later), plus tmpfs on `/run`,
  `/run/lock` and `/tmp`. Never `--privileged`.
- **Stopping** takes longer than Docker's default 10 seconds, because
  systemd stops PostgreSQL and the services in order. Give it 60 seconds
  (`docker stop -t 60`); a kill can leave PostgreSQL recovering on the next
  start.
- **The console's address:** the console checks that the request's host
  matches the name it was set up for, so publish it on host port 443. A
  different host port answers 421 until #606 handles it.

## Failure behaviour

- If Repair fails at start, `openvibes-container-start.service` fails and
  the services Repair didn't reach stay off. `docker exec <container>
  journalctl -u openvibes-container-start` shows why. Running Repair again
  from the TUI is safe.
- On a cgroup v1 host, systemd can't start under Docker without extra
  flags, and the container exits at once.

## How to test

`bash scripts/container-e2e.sh [IMAGE]` checks, with Docker or Podman,
that:

1. the image boots unprivileged with no failed unit;
2. Setup works inside it, and the console answers on the published port;
3. a new container on the same volumes keeps the CA and the database, has
   no files without an owner, and starts the services by itself.

`KEEP=1` leaves the container and its volumes for a look afterwards.
