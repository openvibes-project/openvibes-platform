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
