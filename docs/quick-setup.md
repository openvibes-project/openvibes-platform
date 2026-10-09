# Quick setup

From nothing to a platform, a second host reporting to it, and its first
results in the web console. You need two Fedora 44 x86_64 hosts that can
reach each other, and sudo on both.

Walked through for real on 2026-10-08 (release 0.2.5, two blank lab
machines); what was unclear then is being fixed, and this page follows.

## 1. Install the platform

On the platform host, as your own user (not root):

```sh
sudo sh -c "$(curl -fsSL https://openvibes-project.github.io/install.sh)"
```

(Piped as `curl … | sudo sh`, it installs but cannot open Setup, because a
pipe is not a terminal; it then tells you to run `sudo openvibes-admin`.)

Prefer to read it first: `curl -fsSLO https://openvibes-project.github.io/install.sh`,
read it, then `sudo sh install.sh`.

The script adds the signed OpenVIBES package repository (it checks the key's
fingerprint), installs `openvibes-admin` and opens its **Setup** screen.

## 2. Run Setup

The Setup form has the components ticked (ingest, console, distribution,
vulnerabilities, rules and an agent on this host), a hostname and a CA
mode, and the ports. The defaults are right for a first install:
enter the hostname the other hosts will use to reach this one and press
`Start`. The console port is 443 unless another web server already holds
it; then the form proposes the first free port from 8443 and says so, and
the console is at `https://HOST:PORT`. The agent ports (18423, 18424) move
the same way, and the install command and package the console hands out
(step 3) carry them. To move a
port later: `sudo openvibes-admin setup --repair --console-port N` (or
`--ingest-port`, `--distribution-port`, which also need
`--move-agent-ports`: agents on other hosts then need their install line
run again). Setup asks for
your password once and then shows each step as it runs: packages,
PostgreSQL, database, CA, certificates, console, services, firewall
(the console and agent ports), agent, readiness and the assistant model. A port another
process holds stops Setup before any service starts, naming the process. If a step fails, fix the cause
and press `r` to continue from it.

**The CA's root key.** In the default (quick) CA mode, Setup writes the
root key once to the form's *Root key file*, by default
`~/openvibes-root-ca.key`, and keeps no other copy. It is the only way to
issue a new intermediate certificate later, so copy it to offline
storage and then delete it from the host. Without it, a new CA means
re-enrolling every agent.

**The assistant (optional).** Tick `assistant` in the form to have the
console's chat assistant. Setup then asks "Download the assistant's model
(2.5 GB from Hugging Face)?" and shows the model's licence: answer **Y**
and Setup downloads it, checks it against its pinned checksum and turns the
assistant on. Answer **N** and the assistant stays off; the last screen
says so. No internet on the platform host: see the [offline install guide](components/offline-kit.md).

**Adding the assistant later:** open Setup (`sudo openvibes-admin`), turn the
assistant on with `m` (change components) and answer **Y**.

The last screen shows, once:

- the console address and the `admin` password: **write the password down**;
- where the root key was written (move it offline, then delete it there);
- what to do next: sign in, change the password, then add hosts from the
  console (Enrollment).

Without a terminal, this does the same (keep the `--root-key-out` file as
above; without it the root key is deleted):

```sh
sudo openvibes-admin setup --quick --components ingest,console,distribution,vulns,rules,agent \
  --hostname NAME --root-key-out /root/openvibes-root-ca.key
```

Details: [`openvibes-admin.md`](components/openvibes-admin.md) (Setup and
the setup command).

## Step 1 (offline): install from the kit

Instead of step 1, for a platform host with no internet. Details:
[`offline-kit.md`](components/offline-kit.md).

1. Download `openvibes-platform-<v>-offline-fedora44.tar`, and optionally the model from the Hugging Face link, in any browser.
2. Copy both to the server, into the same folder.
3. Run `tar xf openvibes-platform-<v>-offline-fedora44.tar && sudo ./openvibes-offline/install`.

Setup opens at the end; continue with step 2. If you copied the model, Setup installs it.

## 3. Add a second host

In the console (step 4 has how to sign in), open **Enrollment**. Under
**Add a host**:

- **Copy CLI install** copies a one-line command: paste it into a root
  shell on the second host;
- **Install package** downloads a script that does the same: copy it to the
  host and run `sudo sh openvibes-agent-install.sh`.

Without the console, `sudo openvibes-admin agent command` on the platform
host prints the same line. It looks like:

```sh
curl -fsSL https://openvibes-project.github.io/install.sh | sudo sh -s -- \
  --agent --platform HOST --token TOKEN --ca-sha256 FINGERPRINT \
  --rules … --alarm-rules …
```

The script fetches the platform's CA, refuses it unless its SHA-256
fingerprint matches, installs `openvibes-agent`, enrolls and prints
`enrolled as agent.…`. Both carry the platform's standing token, which
never expires and enrolls any number of hosts: keep them private, and
revoke the token under Enrollment if one leaks.

## 4. See it in the console

Open `https://HOSTNAME` and sign in as `admin`. The browser warns about the
certificate: it is issued by your platform's own CA (import `root.crt`
from `/etc/openvibes/pki/` into the browser to stop the warning).

- **Hosts:** both hosts; each host's Details say whether its threat alarms
  are on (eBPF or audit), and if not, why and the command that fixes it.
- **Vulnerabilities:** each host's packages matched against the Fedora
  advisories. The vulnerability service checks a feed at startup if a host
  already reports that release, or when the first inventory for a new
  release arrives. Results appear after that check completes.
- **Compliance:** findings from the baseline rules, which Setup publishes.
- **Alarms:** threat alarms (for example a web server starting a shell)
  appear within seconds of the program start.

## Next

- Other hosts: repeat step 3; `openvibes-admin agent list` shows them all.
- Check, repair, update, change components or uninstall: the Setup tab
  (`c`, `r`, `u`, `m`, `x`).
- Services and configuration: the Services and Configuration tabs. Setup
  added you to `openvibes-operators`; log in again before using them.
- Hosts without network access: the agent's `export`, then
  `openvibes-admin import` on the platform.
