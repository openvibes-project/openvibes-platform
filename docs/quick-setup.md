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
curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh
```

Prefer to read it first: `curl -fsSLO https://openvibes-project.github.io/install.sh`,
read it, then `sudo sh install.sh`.

The script adds the signed OpenVIBES package repository (it checks the key's
fingerprint), installs `openvibes-admin` and opens its **Setup** screen.

## 2. Run Setup *(not yet run)*

The Setup form has the components ticked (ingest, console, distribution,
vulnerabilities, rules and an agent on this host), a hostname and a CA
mode. The defaults are right for a first install: enter the hostname the
other hosts will use to reach this one and press `Start`. Setup asks for
your password once and then shows each step as it runs: packages,
PostgreSQL, database, CA, certificates, console, services, firewall
(443, 18423, 18424), agent and readiness. If a step fails, fix the cause
and press `r` to continue from it.

**The CA's root key.** In the default (quick) CA mode, Setup writes the
root key once to the form's *Root key file*, by default
`~/openvibes-root-ca.key`, and keeps no other copy. It is the only way to
issue a new intermediate certificate later, so move it off the host
(offline storage) and delete it there. Without it, a new CA means
re-enrolling every agent.

The last screen shows, once:

- the console address and the `admin` password: **write the password down**;
- the root certificate's fingerprint;
- the one-line command that installs an agent on another host.

Without a terminal, `sudo openvibes-admin setup --quick --components
ingest,console,distribution,vulns,agent --hostname NAME` does the same.
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
  advisories. The first feed download starts with the vulnerability
  service; results appear once it and the agents' first inventories are
  in.
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
