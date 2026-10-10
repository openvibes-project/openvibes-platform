# TUI rework: approved by the user (2026-10-10)

1. Single menu, logo at the top, entries open the thing you want. First
   install shows the installation menu; afterwards the simple menu.
2. Home menu = Take B: figlet logo + "limebox · v0.2.8"; one status line
   ("● All 8 services running   ▲ Certificate expires in 21 days");
   entries Status / Settings / Agents / Maintenance / Quit, each with a
   short description to the right; footer "↑↓ choose   Enter open   q quit".
3. Every screen below the menu keeps the big logo at the top, with the
   screen's name where the host/version sits ("Style 1"). Esc goes back
   one level.
4. Bottom row = "Bar 1": a boxed bar of keys shown as buttons
   ("[Enter] Open ingest  [r] Restart  [s] Stop  [l] Logs   [Esc] Back  [?]"),
   contextual to the selected item; Esc Back and ? Help always at the
   right. User: the bottom row must be clearer and more responsive than
   today.
5. Service screen (Status › ingest): state line (running · ready · since ·
   starts at boot) + one line of what it does; recent log, newest at the
   bottom; bar [r] Restart [s] Stop [b] Don't start at boot [l] Full log
   [Esc] Back. Confirmations replace the bar ("Restart ingest? Agents
   reconnect within a minute. [y] Yes [n] No"); progress and result show
   in the bar (spinner "Restarting ingest…", then "✓ ingest restarted and
   ready (4 s)"). Approved ("yes this is better").
6. New logo = "A: Block letters" (figlet ANSI Shadow style, six rows):
   OPEN in white, VIBES in teal #36b9e0; the screen title / host line
   under it. ("A all the way")
7. Status list rows are uniform: name, state, ready, since. No per-service
   notes ("1 device" removed: "it should be obvious from an admin
   perspective ... that things should be there"). Details live on the
   service's own screen.
8. No "start at boot" switch anywhere (user: disabling would break the
   application). Setup enables, Repair re-enables; a service disabled for
   boot is a Status problem with Enter fix.
9. Service actions are on Status in the bar while a service is
   highlighted (Enter Open, r Restart, s Stop); the service screen only
   shows the service (clear "Service: ingest" header, state, log,
   l Full log). Stop stays in the bar with its warning ("Stop ingest? Agents keep their findings until it runs."); a stopped service is a red problem on Status with Enter Start. Approved with the scroll screens.
10. "↑↓ Move" is the first button in the bar on every screen (user:
    "standard on all the pages"); left out only while the bar asks a
    question or a value is being edited.
11. Lists scroll naturally, one row per step (user): "↑ N more" above and "↓ N more" below count with every move, so you see how far you are; they are dim hints, not selectable rows. Every list.
12. One frame for every screen (user: "the gaps ain't the same"): logo,
    host/title line, exactly one empty line, then content. Everything
    (headers, menus, lists, help) starts at the logo's left edge; the
    highlight marker ▸ sits two columns left of it. Menus (choices of
    where to go: Home, Settings) have one empty line between entries;
    data lists (services, settings, log lines) are compact, one per line.
    Screen header "━━ Name ━━━━" in teal is the first content line where
    a screen has one.
13. Every list everywhere has one empty line between entries (user: step 4
    and 5 gaps differed); longer lists scroll with the counts. Replaces
    the menu/data-list distinction in 12.
14. Settings split (user agreed): the TUI keeps only what is needed when
    the console is down or unreachable — ports and listen addresses
    (console, agent ports, netlog), web address and certificates, database
    connection, console sign-in recovery (reset admin password). Feeds,
    proxy, intervals, NVD key, enrichment, agent limits/timeouts/retention,
    distribution limits, network-device tuning and the assistant move to
    the console's admin pages. The TUI's Settings entry goes; what remains
    lives under Maintenance (Ports and addresses, Certificates, Database).
    Home menu becomes Status / Agents / Maintenance / Quit.
15. Scroll hints ("↑ N more" / "↓ N more") sit inside the one-line gap
    above the first and below the last visible entry, so every gap is
    exactly one line with or without a hint.
16. The line under the logo on every screen: where you are on the left
    (host · screen › subscreen), the version on the right, plus
    "▲ 0.2.9 available" in yellow when an update exists (user).
17. Appliance (VA, future, user): AlmaLinux or Rocky. A regular user who
    SSHes in lands on Home (the TUI is the login experience). The TUI must
    be able to update the underlying OS (dnf). OS updates are on EVERY
    install, not only the appliance (user). Maintenance › Operating system:
    version, last check, updates (security in yellow), kernel = restart
    needed; u Update everything (asks first), c Check again; progress
    survives leaving the screen; done → r Restart now / l Later.
18. Actions are entries on the screen, chosen with ↑↓ and Enter, not
    letter keys the user must press (user: "should not have to press u,
    use arrows instead"). The bar names what Enter does on the highlighted
    entry.
19. OS screen with action entries (Update everything / Check again) approved.
20. Replaces 9 (user: the choices box under a service is "horrible"):
    Enter on a service in Status opens "Service: ingest" — state line, then
    the actions as entries (Restart, Stop, Full log; ↑↓ + Enter, the bar
    names what Enter does), then the latest log lines. Log lines stay
    compact (text, not a list). Questions in the bar have Yes / No buttons
    chosen with ←→ and Enter (y/n still work, not shown). Approved.
21. First install Welcome (user): "Choose what to install" first;
    "Quick install" second, its description saying what it does
    ("everything, with default names and ports"; user: describe what it
    does, not who it is for) — the user sees it as suited to homelabs ("not for
    real environments; it works for homelabs only"), then Quit.
22. Checkboxes are selected with Space; the bar on a checkbox row says
    "Space Select" (user). Enter opens, edits or starts.
23. Quick install opens "Quick install: only what OpenVIBES cannot know":
    Host name (filled in), Other names, Root key file, then Install
    (everything else default). Help line explains the highlighted entry.
    Approved.
24. Quick install also has "[x] Agent on this host — watch this host too",
    ticked by default (user: some people want no agent on the console
    server; not the default). Space selects.
    Approved.
25. The core is always installed and never offered as a choice (user):
    console, agent connections, vulnerabilities, rule distribution,
    own-rule signing, baseline rules. Advanced install step 1 is
    "Optional": [x] Agent on this host (default on), [ ] Assistant
    (default off), Next. Steps: Optional, Names, Certificates, Ports,
    Review.
26. Advanced install step 3, Certificates (user): default "(•) Your own
    CA — your CA signs an intermediate for OpenVIBES" (segmented,
    professional networks); second "( ) OpenVIBES makes one" (new root,
    key offline after). With your own CA the install pauses at the CA
    step: Show the request (plain text to copy, also saved as a file),
    Signed certificate and Your CA's certificate (each: Paste it — a paste
    box checked at once: what it is, who signed it, matches the request,
    valid until — or From a file on this host, browsed with the arrows),
    Continue the install. Approved.
27. With your own CA, the request, the paste and the checks all happen in
    step 3, before Install (user: seeing the install run before the CA
    steps is wrong). Review shows "your own CA · ✓ signed by …"; the
    install then runs start to finish without pausing.
    Whole advanced install flow (16 screens, tui-advanced-full3) approved.
28. Agents leave the TUI (user): the agent appears only at install ("Agent
    on this host"); handling agents — list, adding hosts, tokens, network
    devices — is the console's. Home: Status, Maintenance, Quit.
    Maintenance gains "Optional parts" (agent on this host, assistant) for
    changing them after install. Maintenance list of ten (Update OpenVIBES,
    Operating system, Repair, Optional parts, Ports and addresses,
    Certificates, Database, Console sign-in, Back up, Uninstall) approved.
29. Update OpenVIBES screen: version line + one line of what's new;
    [x] Back up first (default on), Update now, What's new; question in
    the bar; six progress steps; one result line. Repair: checks first,
    lists results (read-only report), Fix N problems / Check again.
    Backup file names are unique per update (user: today it complains the
    backup name already exists): ~/openvibes-<target version>-<date>-<time>.dump.
    Update + Repair mockups approved ("the mockup looks amazing").
30. Every question in the bar has one form (user: "make sure it says
    enter to confirm"): question + short detail on the left; on the right
    Yes / No buttons, ←→ and "Enter Confirm".
31. Every checkbox row's bar (user): "Space Select/deselect  Enter Confirm".
    Rules 30 and 31 are standard on all pages (user).
    Optional parts + Ports and addresses approved.
32. On one screen, information rows and entries share one value column.
33. Nothing the platform does automatically gets a button (user: "why
    should we even have the clean up option? That should happen
    automatically"). Database is a report: schema, size, data kept (set in
    the console), automatic nightly clean-up with last run and what it
    removed. Back up stays its own Maintenance entry.
34. Certificates (user): web and agent certificates are renewed
    automatically under OpenVIBES's intermediate (no Renew button, rule 33;
    Status warns only if a renewal fails). Entries: Names, Replace the
    intermediate. With your own CA, replacing uses the install flow (show
    the request, paste or pick the signed certificate, checked at once).
    With the OpenVIBES-made CA it needs the offline root key file.
    Superseded in part by 36; approved.
35. SAML sign-in is a console feature for the whole console, mapped to the
    platform's existing users, roles and permissions (user): its own spec.
    The TUI only gets a place under Console sign-in (single sign-on on/off,
    the local admin as break-glass).
36. Certificates must cover homelabs, normal companies and strict
    segmented networks (user: "huge aspirations"). Two questions:
    Agent certificates — (•) Your CA signs our request (default; key made
    here) / ( ) Import from your PKI (cert + key, or .p12 with password) /
    ( ) OpenVIBES makes its own CA. Web address certificate — (•) From the
    intermediate (renewed automatically) / ( ) Your own certificate (e.g.
    wildcard; you renew it; Status warns before expiry) / ( ) Automatic via
    ACME (Let's Encrypt, or step-ca/Vault/EJBCA inside; ACME server,
    e-mail, HTTP-01 or DNS-01). Maintenance › Certificates shows both parts
    and changes either. ACME explained to and kept by the user. Approved.
37. Every "Back up first" checkbox (Update, Uninstall) is off by default
    and then remembers the user's last choice; the help line says
    "Ticked because you backed up last time" or "Off unless you chose it
    last time"
    (user). Supersedes "default on" in 29. Back up: what is in it, a new
    file name every time, progress, result with size and "copy it off
    this host". Uninstall: (•) Keep the data / ( ) Remove everything
    (type the host name to confirm, ✓ when it matches; nothing left
    behind), Back up first, Uninstall with the standard question.
38. No backup location is shown or assumed by default (user: it differs
    per environment). Ticking Back up first (or opening Back up) asks for
    a folder: type it, or Tab to browse, checked as you type (exists,
    writable, free space). The chosen folder is remembered and shown next
    time; every backup gets its own file name inside it.
    Folder-choice backup flow approved (LGTM).
39. Keys look the same everywhere: shown as key buttons (as in the bar),
    arrows as one button "↑↓" / "←→", never spaced-out text (user).
40. Arrow keys are drawn ⭡⭣ and ⭠⭢, bold, in key buttons (user picked
    them in their own terminal: "⭡⭣ looks best"). Fallback: on the Linux
    text console (TERM=linux, e.g. the appliance's local screen) and any
    terminal without them, plain ↑↓ ←→.
41. General screens approved: Help (? anywhere: keys as buttons in two
    spaced columns + what keys do on the screen you came from); a failed
    step (red ✗, what failed, why, what to do, that nothing broke, Enter
    Try again); wrong password in the bar with tries left; q while work
    runs asks, the work carries on; Console sign-in (Reset the admin
    password; Single sign-on on/off, set up in the console; local admin is
    the break-glass account); a too-small window shows one sentence.
42. Both whole flows (Update OpenVIBES from Home and back; full advanced install) confirmed by the user.
43. Appliance only (in review): Home adds System and replaces Quit with
    Log out (the TUI is the SSH session). System: Network, Time (NTP,
    time zone), Login password, SSH, Restart, Shut down (standard
    question). Network holds the address (DHCP / fixed, filled from DHCP,
    gateway), DNS ([x] DNS from DHCP, or your own servers checked before
    Apply, search domain) and the host name, one screen (user).
    Appliance screens approved ("LGTM finally it looks like I want it"). Scroll hints stay inside the gap (rule 15).
44. Maintenance › Shell (user): second to last, before Uninstall; standard question, then the login password; a plain shell with one line "type exit to go back to the menu", logged; exit returns to Maintenance. On normal installs it opens the user's shell. Approved in context (SSH login → Log out).
