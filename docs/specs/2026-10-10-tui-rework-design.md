# TUI rework: one menu, full screens, every flow key by key

Design session with the user, 2026-10-10. The functions of today's
`openvibes-admin` TUI stay; the user experience is rebuilt from the
start. The user rejected the current UX on every count (finding things,
look, flows, feedback, keys) and approved the new design screen by screen
through full-size mockups.

- **Reference mockups:** `docs/specs/tui-rework/` — the generator
  (`gen.py`), one script per page, and `approved.md` (every decision in
  the order it was made, 44 entries, superseded ones marked). Rendering a
  page: `python3 -I docs/specs/tui-rework/<page>.py docs/specs/tui-rework`
  prints an HTML fragment of 80×24 screens. **The mockups are the
  contract:** where this text and a mockup disagree, the later approved
  mockup wins.
- **Today's TUI** (what must keep working): every function and where it
  goes is in §9.

## 1. Principles (user)

1. **One menu.** The logo on top, a short menu, each entry opens what it
   says. A host without OpenVIBES opens the install menu instead.
2. **Arrows and Enter, never letters to learn.** Actions are entries on
   the screen; ⭡⭣ moves, Enter does, Space selects, ⭠⭢ answers questions,
   Esc goes back. Letter keys may exist as shortcuts but are never needed
   and never shown, except `q` (quit, from Home) and `?` (help).
3. **The same everywhere.** One frame, one spacing, one bar, one way to
   ask, one look for keys. The user spots any difference immediately.
4. **The TUI is for the host; the console is for the product.** The TUI
   keeps what is needed when the console is down or unreachable, or to
   set up and maintain the host. Everything about how the security
   features behave lives in the console (§8).
5. **Nothing automatic gets a button.** What the platform does by itself
   (nightly clean-up, certificate renewal) is shown as done, with when.
6. **Nothing left behind, no unsafe values** (project rule): uninstall
   removes everything it says; every input is checked as it is typed.
7. **Built for homelabs and strict enterprises alike.** Defaults suit a
   professional, segmented network; the quick paths are labelled for
   what they do.

## 2. The frame (every screen)

```
    ██████╗ ██████╗ ███████╗███╗   ██╗██╗   ██╗██╗██████╗ ███████╗███████╗   logo: OPEN white,
    …  (six rows, figlet "ANSI Shadow")                                      VIBES teal #36b9e0
    limebox · Maintenance › Certificates          v0.2.8  ▲ 0.2.9 available
                                                   ← where you are · version (+ update, yellow)
    ━━ Certificates ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━   header (teal rule)
                                                    ← exactly one empty line
    content…
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ [⭡⭣] Move  [Enter] Renew now                              [Esc] Back  [?] │  bar
 └──────────────────────────────────────────────────────────────────────────┘
```

- **Logo:** six rows, block letters; under it the location line: host ·
  screen › subscreen on the left, the version on the right and, when an
  update exists, "▲ x.y.z available" in yellow. On every screen.
- **One empty line** under the location line, then content. Everything
  starts at the logo's left edge (column 4); the highlight `▸` sits two
  columns left of it, the highlighted row has a teal background.
- **Lists:** one empty line between every two entries, on every list.
  Lists longer than the screen scroll one row per step; "⭡ N more" and
  "⭣ N more" are dim hints inside the gap above the first and below the
  last visible entry and count with every step. They are not entries.
  Headings sit directly on their list. Read-only reports (log lines,
  check results, information rows) are compact text, one per line.
- **One value column per screen:** information rows and entries align.
- **Help line:** the line under a list explains the highlighted entry.
- **The bar** (bottom, boxed): keys as buttons. Left: `⭡⭣ Move` first
  (always, except while a question is asked or a value typed), then what
  Enter (or Space) does on the highlighted entry, named ("Enter Restart
  ingest"). Right: `Esc Back` and `?`. On Home: `q Quit` and `?`.
- **Questions** replace the bar: the question and a short detail on the
  left; on the right `Yes` / `No` buttons, `⭠⭢` and `Enter Confirm`.
  `y`/`n` work too, unshown. Every question looks like this.
- **Checkbox rows:** the bar says `Space Select/deselect  Enter Confirm`.
- **Typing a value:** in place, with a cursor; the bar says what is being
  typed, `Enter Done`, `Esc Cancel`; checked as it is typed ("18500 is
  free on this host", "exists and is writable · 1.8 TB free").
- **Work in progress** shows in the bar (spinner, step) and on screen
  (steps with ✓ / spinner / ·, what the current step does); never a frozen
  screen. The result is one line: "✓ … (time)". Leaving the screen does
  not stop work; Home shows when it is done. Quitting while work runs asks.
- **Errors:** red ✗ on the step; what failed, why, what to do, and that
  nothing was broken; `Enter Try again`. A wrong password is said in the
  bar with the tries left.
- **Keys look the same everywhere:** buttons; arrows drawn `⭡⭣` / `⭠⭢`
  in bold. Fallback to `↑↓ ←→` on the Linux text console (`TERM=linux`)
  and terminals without those glyphs.
- **Minimum size 80×24;** smaller shows one sentence ("This window is
  60×18. OpenVIBES needs at least 80×24: make the window larger.").
- **Help (`?`):** every key as a button in two spaced columns, plus what
  the keys do on the screen you came from.

## 3. Screen tree

```
Install (host without OpenVIBES)            Home (installed)
├─ Choose what to install  (5 steps)        ├─ Status
├─ Quick install                            │   └─ Service: <name>
└─ Quit                                     ├─ Maintenance
                                            │   ├─ Update OpenVIBES
                                            │   ├─ Operating system
                                            │   ├─ Repair
                                            │   ├─ Optional parts
                                            │   ├─ Ports and addresses
                                            │   ├─ Certificates
                                            │   ├─ Database          (report)
                                            │   ├─ Console sign-in
                                            │   ├─ Back up
                                            │   ├─ Shell
                                            │   └─ Uninstall
                                            ├─ System               (appliance only)
                                            │   ├─ Network  (address, DNS, host name)
                                            │   ├─ Time
                                            │   ├─ Login password
                                            │   ├─ SSH
                                            │   ├─ Restart
                                            │   └─ Shut down
                                            └─ Quit  (appliance: Log out)
```

There is no Settings and no Agents entry (§8).

## 4. Home and Status

- **Home:** one status line (all services running, or the problems; OS
  security updates), then Status, Maintenance, (System,) Quit, each with a
  description of what it opens.
- **Status:** "Needs attention" first (problems, each with what Enter
  does: renew, start, fix), then Services, uniform rows (name, state,
  ready, since; no per-service notes), then checks. A stopped service is a
  red problem with `Enter Start`; a service not enabled at boot is a
  problem with `Enter Fix`. There is **no boot switch** anywhere: Setup
  enables, Repair re-enables.
- **Service: <name>** (Enter on a service): a header that says which
  service; its state line (running · ready · since · one useful fact);
  then **Restart**, **Stop**, **Full log** as entries (the bar names what
  Enter does); then the latest log lines. Restart and Stop ask with the
  standard question; Stop says what stops working ("Agents keep their
  findings until it runs"). Result in the bar.

## 5. Install

**Welcome:** "This host does not run OpenVIBES yet." Entries: **Choose
what to install** (first: components, names, ports), **Quick install**
(described by what it does: "everything, with default names and ports"),
**Quit**.

**Quick install** (one screen, "only what OpenVIBES cannot know"): Host
name (filled in), Other names, Root key file, `[x] Agent on this host`
(on by default; untick only if this server must not run an agent),
Install. Quick install uses OpenVIBES's own CA and the web certificate
from it; every other choice is the default.

**Choose what to install**, five steps with a steps line
(✓ done · ● current · ○ to come); `Enter` on Next moves on, `Esc` goes
back a step:

1. **Optional:** `[x] Agent on this host`, `[ ] Assistant` (2.7 GB).
   The core is always installed and never offered: console, agent
   connections, vulnerabilities, rule distribution, own-rule signing,
   baseline rules.
2. **Names:** host name, other names; edited in place.
3. **Certificates**, two questions:
   - *Agent certificates:* **(•) Your CA signs our request** (default;
     key made here, never leaves) · ( ) **Import from your PKI** (finished
     intermediate: certificate + key as PEM, or a `.p12` with its
     password) · ( ) **OpenVIBES makes its own CA** (homelab; root key
     written once, moved offline).
   - *Web address certificate:* **(•) From the intermediate** (renewed
     automatically) · ( ) **Your own certificate** (e.g. a wildcard; you
     renew it; Status warns before it expires) · ( ) **Automatic via ACME**
     (Let's Encrypt, or an internal ACME server: step-ca, Vault, EJBCA;
     server URL, account e-mail, HTTP-01 or DNS-01).
   - With *Your CA signs our request*, the request is made **in this
     step, before Install**: Show the request (plain text to copy, also
     saved as a file), Signed certificate, Your CA's certificate (each:
     **Paste it** into a box checked at once — what it is, who signed it,
     that it matches the request, valid until — or **From a file on this
     host**, browsed with the arrows), Next once both are added. The
     install never pauses for the CA.
4. **Ports:** console, agent connections, rule distribution, network
   devices (514/udp, "open it in your firewall"); a taken port is flagged
   ("443 is in use by nginx · 8443 proposed") before anything installs.
5. **Review:** every choice; Enter on a line jumps back to its step;
   Install asks the sudo password once, in the bar, never stored.

**Installing:** steps with state and current action, start to finish.
**Finished:** labelled rows — console address, sign in as, password
(shown once, "write it down"), certificates (who signed them, or the root
key file to move offline), next steps — `Enter Continue to Home`.

## 6. Maintenance

| Entry | What it shows and does |
|---|---|
| **Update OpenVIBES** | Installed and available version, one line of what is new. `Back up first` (off by default, then the last choice; no folder until you choose one, then remembered; a new file name each time), Update now, What's new. Standard question, six steps, one result line. |
| **Operating system** | Distribution, kernel, last check; updates (security in yellow), whether a restart is needed. Entries: Update everything, Check again. Runs on, also when you leave; done → Restart now / Later. **On every install** (user), not only the appliance. |
| **Repair** | Checks first and lists the results (report); Fix N problems / Check again. |
| **Optional parts** | Agent on this host, Assistant as checkboxes; Apply with the standard question. |
| **Ports and addresses** | Every listening port; edit in place, checked as typed; Apply says the consequence ("Agents on other hosts need their install line again"). |
| **Certificates** | Both parts and how each is issued (renewal is automatic, shown with the next date); Names; change how agent certificates are issued (incl. replacing the intermediate: the install flow); change the web address certificate (renew your own, ACME details). |
| **Database** | Report only: schema, size, data kept (set in the console), automatic nightly clean-up with last run and what it removed. |
| **Console sign-in** | Reset the admin password (new one shown once, change at next sign-in); Single sign-on on/off (set up in the console); the local admin stays a break-glass account. |
| **Back up** | What a backup holds; Save in folder (you choose; remembered); Back up now; progress; result with size and "copy it off this host". |
| **Shell** | The operating system's shell in the same session, for experts: standard question, then the login password, logged; one line "type exit to go back to the menu"; `exit` returns to Maintenance. |
| **Uninstall** | (•) Keep the data / ( ) Remove everything (type the host name, ✓ when it matches; "nothing is left behind"); Back up first (as in Update); standard question. |

## 7. Appliance

The appliance (VA) runs AlmaLinux or Rocky (dnf). A user who SSHes in
lands on Home: the TUI is the login experience; Quit becomes **Log out**
and ends the session. Home adds **System**:

- **Network:** DHCP or fixed address (fields filled from DHCP), gateway;
  DNS (`[x] DNS from DHCP`, or your own servers, checked before Apply),
  search domain; host name — one screen.
- **Time** (NTP servers, time zone), **Login password**, **SSH** (keys,
  passwords), **Restart**, **Shut down** (standard question).

## 8. What moves out of the TUI

- **To the console's admin pages** (a console project of its own): feeds,
  proxy, check intervals, NVD key, enrichment; agent connection limits,
  timeouts, finding retention; distribution limits; network-device
  tuning; the assistant's backend, model and privacy options.
- **Agents** are handled in the console (list, adding hosts, enrollment
  tokens, network devices). The TUI asks only about the agent on this
  host, at install and under Optional parts.
- **SAML single sign-on** is a console feature for the whole console,
  mapped onto the platform's users, roles and permissions: its own spec.
  The TUI only turns it off and keeps the break-glass admin.

## 9. Today's TUI → the new one

All functions survive; where they go:

| Today | New |
|---|---|
| Setup tab: form, Start, checklist, finished screen | Install (Welcome, Quick, five steps, Installing, Finished) |
| Setup status: c check, r repair, m components, p ports, u update, x uninstall | Maintenance: Repair, Optional parts, Ports and addresses, Update OpenVIBES, Uninstall |
| Services tab: start/stop/restart, boot enable/disable, logs | Status and Service: <name> (no boot switch; Repair re-enables) |
| Configuration tab (71 fields, 5 files) | Ports/addresses, certificates, database connection stay (Maintenance); the rest moves to the console (§8) |
| Database tab: status, migrate, maintenance now | Database report; migrations run on upgrade; clean-up is automatic |
| Health tab | Status (Needs attention, checks) |
| Model download prompt | Optional parts › Assistant |

## 10. New behaviour behind the screens (backend)

Each needs its own design detail in its plan; listed so nothing is lost:

1. Backup files named `openvibes-<target version>-<date>-<time>.dump` in
   a folder the user chooses; the folder and the "back up first" choice
   remembered (today a fixed name collides on the second update).
2. OS updates through a root helper verb (`dnf check-update`,
   `dnf upgrade`, `needs-restarting -r`), on every install.
3. CA modes: CSR before install (no packages needed), import of an
   intermediate (PEM or PKCS#12 with password), own root; PEM paste and
   file checks (chain, key match, validity).
4. Web certificate separate from agent certificates: from the
   intermediate, user-supplied (with expiry warning), or ACME (client,
   HTTP-01/DNS-01, renewal).
5. Automatic renewal of agent and web certificates under the
   intermediate; Status warns only on failure.
6. Own-rule signing always installed (was optional).
7. The Repair check report as data (each check: ok / problem / fix).
8. Appliance: network (NetworkManager), DNS, host name (hostnamectl),
   time (chrony, timedatectl), login password, SSH settings,
   restart/shut down — root helper verbs with allow-lists.
9. Shell entry: spawn the user's login shell on the same terminal,
   audited (`audit note`), back to the TUI on exit.
10. Glyph fallback for `TERM=linux`.
11. Quit-while-running: background jobs outlive the screen; Home shows
    their result.

## 11. Testing

- **Every approved mockup screen is a test.** Screens render to ratatui's
  `TestBackend` at 80×24 and are compared as text against fixtures taken
  from the mockups (`docs/specs/tui-rework/`), so the frame, spacing and
  bar rules cannot drift.
- Key-by-key flow tests drive the App with fake hosts (as today) through
  the approved flows: install (quick, advanced with each CA mode), update
  with and without backup, repair, uninstall both ways, shell, appliance
  network.
- Layout rule tests: one empty line after the location line; list gaps;
  scroll hints counting; value columns aligned; ⭡⭣ first in the bar.
- The lab (`openvibes-lab`) runs the install and update flows on fresh
  Fedora, Alma and Rocky VMs, and over SSH.

## 12. Build order (sub-projects, each with its own plan)

1. **Frame and navigation:** the frame, bar, lists, questions, help,
   errors, keys and fallback; Home and Status/Service on today's backend.
   Replaces today's tab bar; Setup, Services, Configuration, Database and
   Health keep working behind the new screens until their parts land.
2. **Maintenance on today's backend:** Update (with the backup naming
   and folder memory), Repair report, Optional parts, Ports, Database
   report, Console sign-in, Back up, Uninstall, Shell.
3. **Install:** Welcome, Quick, five steps, Installing, Finished, with the
   CA modes today's backend has (CSR before install, own root).
4. **Certificates backend:** PKI import (PEM/PKCS#12), web certificate
   choices, ACME, automatic renewal; then their TUI screens.
5. **Operating system updates.**
6. **Console admin settings pages** (console; the TUI's Configuration
   fields leave only when these exist).
7. **SAML** (console, own spec).
8. **Appliance:** System screens and the appliance image (when the VA is
   built).
