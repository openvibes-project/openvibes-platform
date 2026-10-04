# Quick setup

From nothing to a platform, a second host reporting to it, and its first
results in the web console. You need two Fedora 44 x86_64 hosts that can
reach each other, and sudo on both.

> **Draft.** The package repository has no packages until the first
> release (v0.1.0) is tagged. The steps marked *(not yet run)* follow the
> code and its tests but have not been walked through for real.

## 1. Install the platform *(not yet run)*

On the platform host, as your own user (not root):

```sh
sudo sh -c "$(curl -fsSL https://openvibes-project.github.io/install.sh)"
```

(Piped as `curl … | sudo sh`, it installs but cannot open Setup, because a
pipe is not a terminal; it then tells you to run `openvibes-admin`.)

Prefer to read it first: `curl -fsSLO https://openvibes-project.github.io/install.sh`,
read it, then `sudo sh install.sh`.

The script adds the signed OpenVIBES package repository (it checks the key's
fingerprint), installs `openvibes-admin` and opens its **Setup** screen.

## 2. Run Setup *(not yet run)*

The Setup form has the components ticked (ingest, console, distribution,
vulnerabilities, rules and an agent on this host), a hostname and a CA
mode, and the ports. The defaults are right for a first install:
enter the hostname the other hosts will use to reach this one and press
`Start`. The console port is 443 unless another web server already holds
it; then the form proposes the first free port from 8443 and says so, and
the console is at `https://HOST:PORT`. The agent ports (18423, 18424) move
the same way, and the agent command Setup prints carries them. To move a
port later: `sudo openvibes-admin setup --repair --console-port N` (or
`--ingest-port`, `--distribution-port`, which also need
`--move-agent-ports`: agents on other hosts then need their install line
run again). Setup asks for
your password once and then shows each step as it runs: packages,
PostgreSQL, database, CA, certificates, console, services, firewall
(the console and agent ports), agent and readiness. A port another
process holds stops Setup before any service starts, naming the process. If a step fails, fix the cause
and press `r` to continue from it.

**The CA's root key.** In the default (quick) CA mode, Setup writes the
root key once to the form's *Root key file*, by default
`~/openvibes-root-ca.key`, and keeps no other copy. It is the only way to
issue a new intermediate certificate later, so copy it to offline
storage and then delete it from the host. Without it, a new CA means
re-enrolling every agent.

The last screen shows, once:

- the console address and the `admin` password: **write the password down**;
- the root certificate's fingerprint;
- the one-line command that installs an agent on another host.

Without a terminal, this does the same (keep the `--root-key-out` file as
above; without it the root key is deleted):

```sh
sudo openvibes-admin setup --quick --components ingest,console,distribution,vulns,rules,agent \
  --hostname NAME --root-key-out /root/openvibes-root-ca.key
```

Details: [`openvibes-admin.md`](components/openvibes-admin.md) (Setup and
the setup command).

## 3. Add a second host *(not yet run)*

On the platform host, print a fresh agent command (the one from Setup's
last screen also works for 24 hours):

```sh
sudo openvibes-admin agent command
```

Run the line it prints on the second host. It looks like:

```sh
curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- \
  --agent --platform HOST --token TOKEN --ca-sha256 FINGERPRINT
```

The script fetches the platform's CA, refuses it unless its SHA-256
fingerprint matches, installs `openvibes-agent`, enrolls and prints
`enrolled as agent.…`. The token works 10 times in 24 hours.

## 4. See it in the console *(not yet run)*

Open `https://HOSTNAME` and sign in as `admin`. The browser warns about the
certificate: it is issued by your platform's own CA (import `root.crt`
from `/etc/openvibes/pki/` into the browser to stop the warning).

- **Agents:** both hosts, with their health.
- **Vulnerabilities:** each host's packages matched against the Fedora
  advisories. The vulnerability service checks a feed at startup if a host
  already reports that release, or when the first inventory for a new
  release arrives. Results appear after that check completes.
- **Findings:** rule findings appear once a rule set is published. The
  baseline rules package is not released yet, so Setup skips its `rules`
  step for now.

## Next

- Other hosts: repeat step 3; `openvibes-admin agent list` shows them all.
- Check, repair, update, change components or uninstall: the Setup tab
  (`c`, `r`, `u`, `m`, `x`).
- Services and configuration: the Services and Configuration tabs. Setup
  added you to `openvibes-operators`; log in again before using them.
- Hosts without network access: the agent's `export`, then
  `openvibes-admin import` on the platform.
