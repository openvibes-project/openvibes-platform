# TUI rework, sub-project 2a: Maintenance on today's backend (Update, Repair, Database, Back up, Uninstall) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Split.** Spec §12 step 2 is too big for one reviewed plan: it has nine pages, four of which need backend changes, and today's Setup screen can only be deleted once all of them exist. **2a (this plan, in full):** the background work runner, the Maintenance menu, Database, Back up, Update OpenVIBES, Repair and Uninstall, and the deletion of today's Database screen and of Setup's check, repair, update and uninstall paths. **2b (outlined at the end, its own plan later):** Optional parts, Ports and addresses, Certificates › Names, Console sign-in and Shell, then today's Setup screen goes for set-up hosts.

**Goal:** Replace the interim Maintenance menu and today's Database screen, and Setup's c/r/u/x paths, with the approved Maintenance pages on today's backend. Long steps run on another thread, the password is asked in the bar, backups get unique names in a folder the user chooses (remembered), a failed update starts the services again, and Uninstall leaves nothing behind.

**Architecture:**
- **`tui/run.rs`** runs a `Work` (a list of helper `Call`s) from a given step on a `Worker` thread, which owns a `Native` host. Progress comes back on a channel that `App::tick` polls, so the screen never freezes. Without a worker (tests), the calls run at once on the TUI's own host.
- The **password** is typed in the bar (`Asking`), moved into the worker, and dropped when its work ends. A wrong password stops the run, the bar asks again with the tries left, and the run resumes at the same step.
- **`tui/maint/`** holds the menu (`mod.rs`) and one module per page. Pages draw through `ui::frame`, `ui::list`, `ui::bar` and the new `ui::steps`.
- **Backend:** the helper remembers the backup folder and the "Back up first" choice in `/etc/openvibes/backup.toml`. The job mark becomes readable, so the TUI sees a half-done update. A new last remove step, `RemoveStep::Admin`, removes `openvibes-admin` itself, what rpm kept of it, and the package repository.

**Tech Stack:** Rust 2024, ratatui 0.30, `platform_host::Host` (adds `free_space`), `std::sync::mpsc`, chrono (local time for file names), toml / toml_edit (all already dependencies).

**Spec:** `docs/specs/2026-10-10-tui-rework-design.md` (§1, §2, §6, §9, §10.1, §10.11, §11, §12 step 2). Mockups in `docs/specs/tui-rework/`: `maint1.py` (Update, Repair), `maint3.py` (Database), `maint4.py` (Back up, Uninstall), `backupfolder.py`, `backupdefault.py`, `flows.py` (the whole Update flow), `general.py` (failed step, wrong password, quitting while work runs, Help), `home3.py` and `shell.py` (the Maintenance list). Decisions: `approved.md` 28–33, 37, 38, 41, 42.

## Decisions the plan makes

The spec and mockups are silent or ambiguous on these points. Each one can be overruled.

1. **Split into 2a and 2b** (above). Why: each half ends with a working, gated TUI, and no review covers more than about ten tasks.
2. **Entries whose backend belongs to a later step are not listed yet.** Operating system comes in step 5. Changing how certificates are issued comes in step 4 (the Names part is in 2b). The single sign-on row of Console sign-in comes in step 7. Why: spec §2 says no key is shown that does nothing.
3. **Settings files (today's Configuration screen) stays as a Maintenance entry until step 6.** Why: spec §12 step 6 says "the TUI's Configuration fields leave only when [the console's admin pages] exist", and §9 says every function survives. *Spec gap:* the approved list has no such entry, and §9 keeps the database connection and TLS paths in Maintenance for good, but no mockup says where.
4. **The interim entry "Components and ports"** opens today's Setup screen, with only `m` and `p` left, until 2b replaces it with Optional parts and Ports. Why: no function is lost meanwhile.
5. **The backup memory belongs to the root helper** (`/etc/openvibes/backup.toml`, 0644, holding the folder and "first"). The helper records the folder after every backup it writes. With `--remember-choice`, it also records whether Update or Uninstall backed up first. Why: the TUI cannot write under `/etc`; a file in the user's home would survive Remove everything (residue); and Remove everything already deletes `/etc/openvibes`.
6. **Backup file names carry the version the dump belongs to:** `openvibes-<target>-<date>-<HHMM>.dump` for Update, and `openvibes-<installed>-<date>-<HHMM>.dump` for Back up and Uninstall. `maint4.py`'s `openvibes-backup-…` is not used. A clash gets `-2`, `-3`… Why: spec §10.1, and a restore needs to know the version.
7. **Quitting (`q`, or Ctrl+C) while work runs asks "Quit when it is done?"** On Yes, the TUI quits as soon as the work finishes; a second Ctrl+C quits at once. Why: today's backend drives the steps from the TUI one by one. Quitting mid-way would stop after the current step and leave services stopped, so `general.py`'s "it keeps running" cannot be made true without a detached job runner. *Spec gap.*
8. **A failed update starts the services again when it can.** A failure at Stop or Install packages runs `update-step start` (a "rescue") with the same password. Each failing step gets its own honest message (`general.py` claims "nothing was changed" for every case). Why: the platform must not stay down after a dnf timeout.
9. **After a successful update, Enter starts the new version of the menu** (`exec /usr/bin/openvibes-admin`), instead of "Back to Maintenance". Why: the running binary is the old one, and its version line would be wrong.
10. **Uninstall also removes `openvibes-admin` itself**, what rpm kept of it (`admin.toml`, `.rpmsave`), `/var/lib/openvibes-admin`, the package repository file and its signing key (once no `openvibes-*` package is left). This is a new last step, "Remove the administration tool". It happens in both modes. PostgreSQL stays (approved mockup). The user's root key file and backups stay, named on the result screen. Why: no residue, and no command left for the user to type (today the last line says `sudo dnf remove openvibes-admin`).
11. **No time estimates** ("about 3 minutes") **and no "New: …" line**, because nothing provides them. What's new lists each package's version change and the release notes address. Why: the screens show no invented data.
12. **The password is asked once per action** (Check, then Fix, ask again) and dropped when that work ends. Why: the spec says it is never stored; holding it for a whole visit to a page would mean storing it.
13. **Enter on a checkbox or radio row does the page's action** (it asks the question), as rule 31's "Space Select/deselect Enter Confirm" says.
14. **Tab on a folder field opens a folder browser:** Use this folder, `..`, then the subfolders; ⭡⭣ and Enter. It is reused by step 3's "From a file on this host".
15. **Repair folds the passing steps into one line** ("✓ 11 other steps in order"). Why: there are 14 steps, and 80×24 does not hold them with the entries.
16. **Database "Data kept" shows "90 days of findings"** (the maintenance timer's default), without "(set in the console)" until step 6. `Database::Migrate` and `Database::Maintenance` are removed. Why: migrations run in Update, and the clean-up runs by itself.
17. **A half-done update or uninstall is a Status problem** with "Enter Finish it". The Update page then offers "Finish the update" even when no newer version exists. Why: a dropped SSH session mid-update must not leave the platform down with no way back in the TUI.
18. **Back up now and Fix N problems ask no question:** the password prompt is their confirmation, as in the mockups. Neither destroys anything.
19. **A root-squashed NFS folder passes the folder check,** because the user can write there, but the helper (root) cannot. The backup step then fails with the error, before anything stops. *Known ceiling*, noted in the component page.

## Global Constraints

Copied verbatim from the spec (§1 and §2). They hold on every screen this plan touches:

- **Arrows and Enter, never letters to learn.** Actions are entries on the screen; ⭡⭣ moves, Enter does, Space selects, ⭠⭢ answers questions, Esc goes back. Letter keys may exist as shortcuts but are never needed and never shown, except `q` (quit, from Home) and `?` (help).
- **The same everywhere.** One frame, one spacing, one bar, one way to ask, one look for keys. The user spots any difference immediately.
- **Nothing automatic gets a button.** What the platform does by itself (nightly clean-up, certificate renewal) is shown as done, with when.
- **Nothing left behind, no unsafe values** (project rule): uninstall removes everything it says; every input is checked as it is typed.
- **One empty line** under the location line, then content. Everything starts at the logo's left edge (column 4); the highlight `▸` sits two columns left of it, the highlighted row has a teal background.
- **Lists:** one empty line between every two entries, on every list. Lists longer than the screen scroll one row per step; "⭡ N more" and "⭣ N more" are dim hints inside the gap above the first and below the last visible entry and count with every step. They are not entries. Headings sit directly on their list. Read-only reports (log lines, check results, information rows) are compact text, one per line.
- **One value column per screen:** information rows and entries align.
- **Help line:** the line under a list explains the highlighted entry.
- **The bar** (bottom, boxed): keys as buttons. Left: `⭡⭣ Move` first (always, except while a question is asked or a value typed), then what Enter (or Space) does on the highlighted entry, named ("Enter Restart ingest"). Right: `Esc Back` and `?`. On Home: `q Quit` and `?`.
- **Questions** replace the bar: the question and a short detail on the left; on the right `Yes` / `No` buttons, `⭠⭢` and `Enter Confirm`. `y`/`n` work too, unshown. Every question looks like this.
- **Checkbox rows:** the bar says `Space Select/deselect  Enter Confirm`.
- **Typing a value:** in place, with a cursor; the bar says what is being typed, `Enter Done`, `Esc Cancel`; checked as it is typed ("18500 is free on this host", "exists and is writable · 1.8 TB free").
- **Work in progress** shows in the bar (spinner, step) and on screen (steps with ✓ / spinner / ·, what the current step does); never a frozen screen. The result is one line: "✓ … (time)". Leaving the screen does not stop work; Home shows when it is done. Quitting while work runs asks.
- **Errors:** red ✗ on the step; what failed, why, what to do, and that nothing was broken; `Enter Try again`. A wrong password is said in the bar with the tries left.
- **Minimum size 80×24.**

Plan rules:

- Every file stays under 500 lines.
- `docs/components/openvibes-admin.md` changes in the same commit as the code it describes.
- Intermediate commits may warn about items that a later task first uses (Tasks 1–2 build primitives, as in sub-project 1); Task 10's clippy run must be clean.
- The last task runs the local gate (`../testing.md` §2), the Fedora container check (§3: packaging and uninstall changed) and an 80×24 tmux walk.
- **Never confirm an action on this host: it is the user's production platform.** Answer every question No, and press Esc at every password prompt.

## Review Focus

These are the five failures most likely to hurt an operator. Each is pinned by a test in the task that owns it.

1. **The session ends, or `q`/Ctrl+C is pressed, mid-update, and the services stay stopped.**
   - Task 2: `q_while_work_runs_asks_and_quits_once_it_is_done` and `ctrl_c_while_work_runs_asks_and_a_second_ctrl_c_quits_at_once`.
   - Task 6: `a_half_done_update_is_a_status_problem_and_finishes_without_a_new_version`.
2. **A failed update step leaves the platform down, or the screen claims what is not true.**
   - Task 6: `a_failed_upgrade_starts_the_services_again_and_says_so` and `a_failed_migration_keeps_the_services_stopped_and_says_why`.
3. **Uninstall leaves something behind, or Remove everything runs on a mistyped name.**
   - Task 8: `the_last_step_removes_the_tool_what_rpm_kept_and_the_repository` and `removing_one_part_leaves_the_administration_tool`.
   - Task 9: `remove_everything_needs_the_host_name_typed_exactly`.
   - Task 10: the Fedora container residue check.
4. **A backup collides, overwrites, or goes to a folder that is not there.**
   - Task 4: `a_second_backup_in_the_same_minute_gets_its_own_name` and `the_folder_is_checked_as_typed`.
   - Task 6: `ticking_back_up_first_needs_a_folder_before_update_now`.
5. **A long step freezes the screen, or the password outlives its work.**
   - Task 2: `with_a_worker_the_screen_keeps_drawing_while_the_step_runs` and `a_wrong_password_is_said_in_the_bar_with_the_tries_left_and_the_run_resumes`.
   - The `Secret` moves into the worker and is never kept in `App`; the `asking` prompt is `None` after Enter.

---

### Task 1: `ui` — typed-in-place bar, keys-only bar, wrong-password note, Tab, steps view

**Files:**
- Modify: `crates/openvibes-admin/src/tui/ui/bar.rs`: variants `Edit` and `Only`, constructors `act`, `only` and `edit`, `Typing.note`, and `pub const SPINNER`.
- Create: `crates/openvibes-admin/src/tui/ui/steps.rs`.
- Modify: `crates/openvibes-admin/src/tui/ui/mod.rs` (`pub mod steps;`).
- Modify: `crates/openvibes-admin/src/tui/work.rs`: the existing `Bar::Typing { … }` gets `note: None`.
- Modify: `crates/openvibes-admin/src/tui/app.rs` (`Key::Tab`) and `crates/openvibes-admin/src/tui/mod.rs` (`KeyCode::Tab => Key::Tab`).

**Interfaces:**
- Produces:
  - `Bar::Edit { label: String, what: String, keys: Vec<(String, String)> }`.
  - `Bar::Only { keys: Vec<(String, String)> }`.
  - `Bar::Typing { note: Option<String>, label: String, shown: String, done: String }`.
  - `Bar::act(keys: &[(&str, &str)]) -> Bar`: Keys without ⭡⭣ Move; Esc Back and ? at the right.
  - `Bar::only(keys: &[(&str, &str)]) -> Bar`.
  - `Bar::edit(label: &str, what: &str, keys: &[(&str, &str)]) -> Bar`.
  - `pub const SPINNER: [&str; 10]`.
  - `ui::steps::lines(theme: &Theme, titles: &[String], states: &[Option<StepState>], running: Option<usize>, tick: usize, room: usize) -> Vec<Line<'static>>`.
  - `Key::Tab`.

- [ ] **Step 1: Write the failing tests**

In `ui/bar.rs`'s `mod tests`:

```rust
    #[test]
    fn a_value_typed_in_place_names_it_and_offers_cancel() {
        let bar = Bar::edit("Folder", "type, or", &[("Tab", "to browse"), ("Enter", "Done")]);
        let t = text(&bar.lines(&plain(), 80));
        assert!(
            t[1].starts_with(" │ Folder: type, or  Tab  to browse   Enter  Done"),
            "{:?}",
            t[1]
        );
        assert!(t[1].ends_with(" Esc  Cancel │"), "{:?}", t[1]);
        assert!(!t[1].contains("Move"), "no Move while typing: {:?}", t[1]);
    }

    #[test]
    fn keys_alone_have_no_move_and_nothing_at_the_right() {
        let t = text(&Bar::only(&[("Enter", "Open 0.2.9")]).lines(&plain(), 80));
        assert!(t[1].starts_with(" │  Enter  Open 0.2.9"), "{:?}", t[1]);
        assert!(!t[1].contains("Esc") && !t[1].contains("Move"), "{:?}", t[1]);
        let t = text(&Bar::act(&[("Enter", "Try again")]).lines(&plain(), 80));
        assert!(t[1].starts_with(" │  Enter  Try again"), "{:?}", t[1]);
        assert!(t[1].ends_with("  Esc  Back    ?  │"), "{:?}", t[1]);
    }

    #[test]
    fn a_wrong_password_is_said_before_the_prompt() {
        let bar = Bar::Typing {
            note: Some("Wrong password, 2 tries left.".into()),
            label: "Your password (sudo)".into(),
            shown: "**".into(),
            done: "Update".into(),
        };
        let t = text(&bar.lines(&plain(), 80));
        assert!(
            t[1].contains("Wrong password, 2 tries left. Your password (sudo): **█"),
            "{:?}",
            t[1]
        );
    }
```

(The spacing is the existing `parts` helper's: a button is ` K `, then ` label  `, as in `keys_start_with_move_and_end_with_back_and_help`.)

`ui/steps.rs`, at the bottom:

```rust
#[cfg(test)]
mod tests {
    use platform_host::StepState;

    use super::lines;
    use crate::tui::ui::{logo::text, theme::Theme};

    fn titles(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn every_step_shows_its_state() {
        let t = Theme::new(None, Some("xterm"));
        let names = titles(&["Back up", "Stop services", "Install packages", "Update the database"]);
        let states = vec![
            Some(StepState::Skipped("not chosen".into())),
            Some(StepState::Done("ok".into())),
            None,
            None,
        ];
        assert_eq!(
            text(&lines(&t, &names, &states, Some(2), 0, 10)),
            [
                "    – Back up  not chosen",
                "    ✓ Stop services",
                "    ⠋ Install packages",
                "    · Update the database",
            ]
        );
        let failed = vec![
            Some(StepState::Done("ok".into())),
            Some(StepState::Done("ok".into())),
            Some(StepState::Failed("timed out".into())),
            None,
        ];
        assert_eq!(text(&lines(&t, &names, &failed, None, 0, 10))[2], "    ✗ Install packages");
    }

    #[test]
    fn too_many_steps_fold_the_done_ones_and_count_the_rest() {
        let t = Theme::new(None, Some("xterm"));
        let names: Vec<String> = (1..=14).map(|n| format!("Step {n}")).collect();
        let mut states = vec![None; 14];
        for state in states.iter_mut().take(5) {
            *state = Some(StepState::Done("ok".into()));
        }
        let out = text(&lines(&t, &names, &states, Some(5), 0, 6));
        assert_eq!(out.len(), 6);
        assert_eq!(out[0], "    ✓ 5 steps done");
        assert_eq!(out[1], "    ⠋ Step 6");
        assert_eq!(out[4], "    · Step 9");
        assert_eq!(out[5], "    · 5 more steps");
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin ui::`
Expected: FAIL to compile (`Bar::edit`, `Bar::only`, `Bar::act`, `note`, `steps` missing).

- [ ] **Step 3: Implement**

In `ui/bar.rs`:
- Make the spinner `pub const SPINNER: [&str; 10] = …;`.
- Add the two variants:

```rust
    /// A value typed in place on the screen: what is typed, a hint, its
    /// keys; Esc Cancel at the right (spec §2 "Typing a value").
    Edit {
        label: String,
        what: String,
        keys: Vec<(String, String)>,
    },
    /// Keys alone: no Move and nothing at the right (a finished run).
    Only {
        keys: Vec<(String, String)>,
    },
```

Change `Typing` to:

```rust
    Typing {
        /// Said first, in red ("Wrong password, 2 tries left.").
        note: Option<String>,
        label: String,
        shown: String,
        done: String,
    },
```

Constructors, in `impl Bar`:

```rust
    /// Keys without ⭡⭣ Move (nothing to move between); Esc Back and ? stay.
    pub fn act(keys: &[(&str, &str)]) -> Bar {
        Bar::Keys {
            keys: owned(keys),
            nav: false,
            home: false,
        }
    }
    pub fn only(keys: &[(&str, &str)]) -> Bar {
        Bar::Only { keys: owned(keys) }
    }
    pub fn edit(label: &str, what: &str, keys: &[(&str, &str)]) -> Bar {
        Bar::Edit {
            label: label.to_owned(),
            what: what.to_owned(),
            keys: owned(keys),
        }
    }
```

In `parts`, replace the `Typing` arm and add the two new arms:

```rust
            Bar::Typing {
                note,
                label,
                shown,
                done,
            } => {
                let mut left = Vec::new();
                if let Some(note) = note {
                    left.push(Span::styled(format!("{note} "), theme.red()));
                }
                left.push(Span::styled(format!("{label}: "), theme.bold()));
                left.push(Span::raw(format!("{shown}█  ")));
                left.extend(key("Enter", done));
                let right = vec![Span::styled(" Esc ", theme.key()), Span::raw(" Cancel")];
                (left, right)
            }
            Bar::Edit { label, what, keys } => {
                let mut left = vec![Span::styled(format!("{label}:"), theme.bold())];
                if !what.is_empty() {
                    left.push(Span::raw(format!(" {what}")));
                }
                left.push(Span::raw(" "));
                for (k, l) in keys {
                    left.extend(key(k, l));
                }
                let right = vec![Span::styled(" Esc ", theme.key()), Span::raw(" Cancel")];
                (left, right)
            }
            Bar::Only { keys } => {
                let mut left = Vec::new();
                for (k, l) in keys {
                    left.extend(key(k, l));
                }
                (left, Vec::new())
            }
```

In `work.rs`, the one `Bar::Typing { label: …, shown: …, done: … }` gets `note: None,` as its first field.

In `app.rs`, `enum Key` gets `/// Tab: browse for a folder (a typed folder only).` and then `Tab,`. In `mod.rs`'s key mapping, add `KeyCode::Tab => Key::Tab,` after `KeyCode::Backspace => Key::Backspace,`. Today's screens ignore the key: their handlers have no `Key::Tab` arm.

`ui/steps.rs`:

```rust
//! A run's steps (spec §2 "Work in progress"): ✓ done, the spinner on the
//! one running, ✗ on the one that failed, – skipped (with why), · to come.
//! More steps than room: the leading done ones fold into one line, and
//! the rest is cut with "· N more steps".

use platform_host::StepState;
use ratatui::text::{Line, Span};

use super::{bar::SPINNER, theme::Theme};

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn lines(
    theme: &Theme,
    titles: &[String],
    states: &[Option<StepState>],
    running: Option<usize>,
    tick: usize,
    room: usize,
) -> Vec<Line<'static>> {
    let state = |i: usize| states.get(i).cloned().flatten();
    let row = |i: usize| -> Line<'static> {
        let title = titles[i].clone();
        if running == Some(i) {
            return Line::from(vec![
                Span::raw("    "),
                Span::styled(SPINNER[tick % SPINNER.len()], theme.teal()),
                Span::raw(" "),
                Span::styled(title, theme.bold()),
            ]);
        }
        match state(i) {
            Some(StepState::Skipped(why)) => {
                Line::styled(format!("    – {title}  {why}"), theme.dim())
            }
            Some(s) if s.finished() => Line::from(vec![
                Span::raw("    "),
                Span::styled("✓", theme.green()),
                Span::raw(format!(" {title}")),
            ]),
            Some(_) => Line::from(vec![
                Span::raw("    "),
                Span::styled("✗", theme.red()),
                Span::raw(" "),
                Span::styled(title, theme.bold()),
            ]),
            None => Line::styled(format!("    · {title}"), theme.dim()),
        }
    };
    let n = titles.len();
    if n <= room {
        return (0..n).map(row).collect();
    }
    let done = (0..n)
        .take_while(|&i| running != Some(i) && state(i).is_some_and(|s| s.finished()))
        .count();
    let mut out = Vec::new();
    if done > 0 {
        out.push(Line::from(vec![
            Span::raw("    "),
            Span::styled("✓", theme.green()),
            Span::raw(format!(" {} done", plural(done, "step", "steps"))),
        ]));
    }
    let left = room.saturating_sub(out.len());
    if n - done <= left {
        out.extend((done..n).map(row));
    } else {
        let shown = left.saturating_sub(1);
        out.extend((done..done + shown).map(row));
        out.push(Line::styled(
            format!("    · {} more steps", n - done - shown),
            theme.dim(),
        ));
    }
    out
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin ui::`
Expected: PASS (all `ui::` tests, old and new).

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/tui/ui crates/openvibes-admin/src/tui/work.rs crates/openvibes-admin/src/tui/app.rs crates/openvibes-admin/src/tui/mod.rs
git commit -m "TUI: typed-in-place and keys-only bars, wrong-password note, steps view"
```

---

### Task 2: `run.rs` — work in the background, the password in the bar, quitting while it runs

**Files:**
- Create: `crates/openvibes-admin/src/tui/run.rs`, `crates/openvibes-admin/src/tui/run_tests.rs`.
- Create: `crates/openvibes-admin/src/tui/script_host.rs` (test only). Move these out of `setup_tests.rs`, verbatim: `SetupHost`, its `impl Host`, `app`, `fresh_app`, `app_taken`, `screen`, `type_text`, `PLAN` and `set_up`. Make each of them, and every field of `SetupHost`, `pub(super)`.
- Modify: `setup_tests.rs` (add `use super::script_host::*;` and delete the moved items) and `nav_tests.rs` (`super::setup_tests::fresh_app`, `::set_up` and `::screen` become `super::script_host::…`).
- Modify: `crates/openvibes-admin/src/tui/mod.rs`:
  - `mod run;`, `#[cfg(test)] mod run_tests;` and `#[cfg(test)] mod script_host;`.
  - The worker, set in `run()`.
  - Ctrl+C calls `app.interrupt()`.
- Modify: `crates/openvibes-admin/src/tui/app.rs`:
  - Fields `run`, `load`, `asking`, `worker` and `quit_when_done`.
  - `key()` routes `asking`.
  - `tick()` calls `poll_runs`.
- Modify: `crates/openvibes-admin/src/tui/work.rs`: the quit question, `quit_or_ask`, and the bar for `asking` and `quit_when_done`.
- Modify: `crates/openvibes-admin/src/tui/home.rs`: the Home status line carries `work_note()`.

**Interfaces:**
- Consumes: `ui::bar::{Bar, SPINNER}` (Task 1), `password::{PasswordPrompt, Typed}`, `Host::privileged`, `Host::database`, `Host::logs`.
- Produces (in `run.rs`):
  - `pub enum Call { Status, Repair(Step), Update(UpdateStep, Vec<String>), Remove(RemoveStep, Vec<String>), Database(Database), Logs(Unit, u16) }`.
  - `pub enum Kind { Update { to: String }, Backup { file: String }, Check, Fix, Uninstall { everything: bool }, Report }`, with `background()`, `doing()`, `done()`, `stopped()` and `verb()`.
  - `pub struct Rescue { pub from: usize, pub to: usize, pub calls: Vec<Call> }`.
  - `pub struct Work { pub kind: Kind, pub calls: Vec<Call>, pub rescue: Option<Rescue> }` and `Work::new(kind, calls)`.
  - `pub struct Progress { pub index: usize, pub result: Result<String, HostError> }`.
  - `pub type Worker = Box<dyn Fn(Work, usize, Secret) -> Receiver<Progress>>`.
  - `pub fn execute<H: Host>(host: &H, call: &Call, secret: &Secret) -> Result<String, HostError>`.
  - `pub fn state_of(call: &Call, result: &Result<String, HostError>) -> StepState`.
  - `pub fn goes_on(call: &Call, result: &Result<String, HostError>) -> bool`.
  - `pub fn work_through<H: Host>(host: &H, work: &Work, from: usize, secret: &Secret, report: impl FnMut(Progress) -> bool)`.
  - `pub struct Run { pub work, pub states, pub at, pub started, pub ended, pub wrong }`, with `running()`, `current()`, `stopped_at()`, `ok()`, `rescued(j)` and `took()`.
  - `pub struct Asking { pub work: Work, pub from: usize, pub prompt: PasswordPrompt, pub resume: bool }`.
  - `App` methods: `begin(work, from)`, `read(work)`, `asking_key(key)`, `poll_runs(now)`, `interrupt()` and `work_note() -> Option<Vec<Span>>`.
- App fields:
  - `pub run: Option<Run>`: actions; Home shows it, and Quit waits for it.
  - `pub load: Option<Run>`: reads that may be dropped (`Kind::background()`).
  - `pub asking: Option<Asking>`.
  - `pub worker: Option<Worker>`.
  - `pub quit_when_done: bool`.

- [ ] **Step 1: Move the scripted host**

Create `script_host.rs` with the header below, then move the items listed under **Files** into it. Run `cargo test -p openvibes-admin setup_tests nav_tests`; expected: PASS, the same tests as before.

```rust
//! A scripted host for flow tests: each privileged call returns the next
//! queued answer ("done\tok" once they run out), and the calls and their
//! passwords are recorded.
```

- [ ] **Step 2: Write the failing tests** (`run_tests.rs`)

```rust
//! Work in the background: the password in the bar, wrong passwords,
//! stopping at a failure, the rescue, and quitting while it runs.

use std::{cell::RefCell, rc::Rc, sync::mpsc, time::Instant};

use platform_host::{HostError, Step, StepState, UpdateStep};

use super::{
    app::{Key, Question},
    run::{Call, Kind, Progress, Rescue, Work},
    script_host::{SetupHost, screen, set_up, type_text},
};

type Sender = Rc<RefCell<Option<mpsc::Sender<Progress>>>>;

fn fix(calls: Vec<Call>) -> Work {
    Work::new(Kind::Fix, calls)
}

/// A worker whose progress the test sends by hand.
fn by_hand(app: &mut super::app::App<SetupHost>) -> Sender {
    let sender: Sender = Rc::new(RefCell::new(None));
    let keep = sender.clone();
    app.worker = Some(Box::new(move |_work, _from, _secret| {
        let (tx, rx) = mpsc::channel();
        *keep.borrow_mut() = Some(tx);
        rx
    }));
    sender
}

fn send(sender: &Sender, index: usize) {
    sender
        .borrow()
        .as_ref()
        .unwrap()
        .send(Progress { index, result: Ok("done\tok\n".into()) })
        .unwrap();
}

#[test]
fn the_password_is_asked_in_the_bar_then_every_call_runs_with_it() {
    let mut app = set_up(vec![Ok("done\tok\n".into()), Ok("done\tok\n".into())]);
    app.begin(fix(vec![Call::Repair(Step::Packages), Call::Repair(Step::Postgres)]), 0);
    let text = screen(&app);
    assert!(text.contains("Your password (sudo):"), "{text}");
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.asking.is_none(), "the prompt is gone once Enter is pressed");
    assert_eq!(
        *app.host.calls.borrow(),
        [
            ("setup-step packages --repair".to_owned(), "pw".to_owned()),
            ("setup-step postgres --repair".to_owned(), "pw".to_owned()),
        ]
    );
    assert!(app.run.as_ref().unwrap().ok());
}

#[test]
fn a_wrong_password_is_said_in_the_bar_with_the_tries_left_and_the_run_resumes() {
    let mut app = set_up(vec![Err(HostError::WrongPassword), Ok("done\tok\n".into())]);
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    type_text(&mut app, "bad");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("Wrong password, 2 tries left."), "{text}");
    type_text(&mut app, "good");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow().last().unwrap().1, "good");
    assert!(app.run.as_ref().unwrap().ok());
}

#[test]
fn three_wrong_passwords_stop_the_run_and_nothing_more_runs() {
    let answers = (0..3).map(|_| Err(HostError::WrongPassword)).collect();
    let mut app = set_up(answers);
    app.begin(fix(vec![Call::Repair(Step::Packages), Call::Repair(Step::Postgres)]), 0);
    for _ in 0..3 {
        type_text(&mut app, "bad");
        app.key(Key::Enter);
    }
    assert!(app.asking.is_none());
    assert_eq!(app.host.calls.borrow().len(), 3);
    let run = app.run.as_ref().unwrap();
    assert!(!run.running() && !run.ok());
    assert!(run.states[0].as_ref().unwrap().detail().contains("three wrong passwords"));
}

#[test]
fn a_run_stops_at_the_first_step_that_fails() {
    let mut app = set_up(vec![Ok("failed\tdisk full\n".into())]);
    app.begin(fix(vec![Call::Repair(Step::Packages), Call::Repair(Step::Postgres)]), 0);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow().len(), 1, "nothing after the failure");
    let run = app.run.as_ref().unwrap();
    assert_eq!(run.stopped_at(), Some(0));
    assert_eq!(run.states[0], Some(StepState::Failed("disk full".into())));
}

#[test]
fn a_failure_the_rescue_covers_runs_the_rescue_with_the_same_password() {
    let mut app = set_up(vec![
        Ok("done\tok\n".into()),
        Ok("done\tok\n".into()),
        Ok("failed\ttimed out\n".into()),
    ]);
    let update = |step| Call::Update(step, Vec::new());
    app.begin(
        Work {
            kind: Kind::Update { to: "0.2.9".into() },
            calls: vec![update(UpdateStep::Backup), update(UpdateStep::Stop), update(UpdateStep::Upgrade)],
            rescue: Some(Rescue { from: 1, to: 3, calls: vec![update(UpdateStep::Start)] }),
        },
        0,
    );
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = app.host.calls.borrow();
    assert_eq!(calls[3], ("update-step start".to_owned(), "pw".to_owned()));
    let run = app.run.as_ref().unwrap();
    assert_eq!(run.stopped_at(), Some(2));
    assert_eq!(run.rescued(0), Some(&StepState::Done("ok".into())));
    assert!(!run.running());
}

#[test]
fn root_is_not_asked_for_a_password() {
    let mut app = set_up(vec![]);
    app.host.root = true;
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    assert!(app.asking.is_none());
    assert_eq!(*app.host.calls.borrow(), [("setup-step packages --repair".to_owned(), String::new())]);
}

#[test]
fn with_a_worker_the_screen_keeps_drawing_while_the_step_runs() {
    let mut app = set_up(vec![]);
    let sender = by_hand(&mut app);
    app.begin(fix(vec![Call::Repair(Step::Packages), Call::Repair(Step::Postgres)]), 0);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.run.as_ref().unwrap().running());
    let text = screen(&app);
    assert!(text.contains("Repairing…"), "Home says what runs:\n{text}");
    send(&sender, 0);
    app.tick(Instant::now());
    assert_eq!(app.run.as_ref().unwrap().states[0], Some(StepState::Done("ok".into())));
    assert_eq!(app.run.as_ref().unwrap().current(), Some(1));
    send(&sender, 1);
    app.tick(Instant::now());
    assert!(app.run.as_ref().unwrap().ok());
    assert!(app.host.calls.borrow().is_empty(), "the worker ran them, not the TUI's thread");
    assert!(screen(&app).contains("✓ Repaired"), "Home shows the result");
}

#[test]
fn q_while_work_runs_asks_and_quits_once_it_is_done() {
    let mut app = set_up(vec![]);
    let sender = by_hand(&mut app);
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Char('q'));
    assert!(matches!(app.question, Some((Question::Quit, true))));
    assert!(screen(&app).contains("Quit when it is done?"));
    app.key(Key::Enter);
    assert!(!app.quit, "the work goes on");
    assert!(screen(&app).contains("Quits when it is done"));
    send(&sender, 0);
    app.tick(Instant::now());
    assert!(app.quit);
}

#[test]
fn ctrl_c_while_work_runs_asks_and_a_second_ctrl_c_quits_at_once() {
    let mut app = set_up(vec![]);
    let _sender = by_hand(&mut app);
    app.begin(fix(vec![Call::Repair(Step::Packages)]), 0);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.interrupt();
    assert!(!app.quit && matches!(app.question, Some((Question::Quit, _))));
    app.interrupt();
    assert!(app.quit);
    let mut idle = set_up(vec![]);
    idle.interrupt();
    assert!(idle.quit, "nothing running: Ctrl+C quits");
}
```

- [ ] **Step 3: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin run_tests`
Expected: FAIL to compile (`run` module missing).

- [ ] **Step 4: Implement `run.rs`**

```rust
//! Work that takes long (spec §2): helper calls run one after the other on
//! another thread, so the screen keeps drawing; the password is typed in
//! the bar, moved to that thread and dropped when its work ends. A run
//! stops at the first call that does not finish; a rescue (Update: start
//! the services again) may follow. Without a worker (tests) the calls run
//! at once on the TUI's own host.

use std::{
    sync::mpsc::{Receiver, TryRecvError},
    time::Instant,
};

use platform_host::{
    Database, Host, HostError, Privileged, RemoveStep, Secret, Step, StepState, Unit, UpdateStep,
};
use ratatui::text::Span;

use super::{
    app::{App, Key, Question},
    password::{PasswordPrompt, Typed},
    ui::bar::SPINNER,
};

/// One helper call, or one read for a report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Call {
    /// `setup-status`: every step's state.
    Status,
    Repair(Step),
    Update(UpdateStep, Vec<String>),
    Remove(RemoveStep, Vec<String>),
    /// A database command (no password).
    Database(Database),
    /// The unit's last journal lines, joined (no password).
    Logs(Unit, u16),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    Update { to: String },
    Backup { file: String },
    Check,
    Fix,
    Uninstall { everything: bool },
    /// The Database page's reads.
    Report,
}

impl Kind {
    /// Reads, which may be dropped: Home does not show them, Quit does not wait.
    pub fn background(&self) -> bool {
        matches!(self, Kind::Check | Kind::Report)
    }
    pub fn doing(&self) -> String {
        match self {
            Kind::Update { to } => format!("Updating to {to}"),
            Kind::Backup { .. } => "Backing up".into(),
            Kind::Check => "Checking every step".into(),
            Kind::Fix => "Repairing".into(),
            Kind::Uninstall { .. } => "Uninstalling".into(),
            Kind::Report => "Reading the database".into(),
        }
    }
    pub fn done(&self) -> String {
        match self {
            Kind::Update { to } => format!("Updated to {to}"),
            Kind::Backup { .. } => "Backed up".into(),
            Kind::Check => "Checked".into(),
            Kind::Fix => "Repaired".into(),
            Kind::Uninstall { .. } => "OpenVIBES is removed".into(),
            Kind::Report => "Read".into(),
        }
    }
    pub fn stopped(&self) -> String {
        match self {
            Kind::Update { .. } => "The update stopped".into(),
            Kind::Backup { .. } => "The backup failed".into(),
            Kind::Check => "The check failed".into(),
            Kind::Fix => "The repair stopped".into(),
            Kind::Uninstall { .. } => "The uninstall stopped".into(),
            Kind::Report => "The database could not be read".into(),
        }
    }
    /// What Enter does once the password is typed.
    pub fn verb(&self) -> &'static str {
        match self {
            Kind::Update { .. } => "Update",
            Kind::Backup { .. } => "Back up",
            Kind::Check => "Check",
            Kind::Fix => "Fix",
            Kind::Uninstall { .. } => "Uninstall",
            Kind::Report => "Read",
        }
    }
}

/// A stop at a main call in `from..to` runs `calls` next, same password.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Rescue {
    pub from: usize,
    pub to: usize,
    pub calls: Vec<Call>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Work {
    pub kind: Kind,
    pub calls: Vec<Call>,
    pub rescue: Option<Rescue>,
}

impl Work {
    pub fn new(kind: Kind, calls: Vec<Call>) -> Work {
        Work { kind, calls, rescue: None }
    }
}

/// One call's result; `index` counts the main calls, then the rescue's.
pub struct Progress {
    pub index: usize,
    pub result: Result<String, HostError>,
}

/// Runs `work` from `from` on another thread with its own host.
pub type Worker = Box<dyn Fn(Work, usize, Secret) -> Receiver<Progress>>;

pub fn execute<H: Host>(host: &H, call: &Call, secret: &Secret) -> Result<String, HostError> {
    match call {
        Call::Status => host.privileged(Privileged::SetupStatus, secret),
        Call::Repair(step) => host.privileged(Privileged::Repair(*step), secret),
        Call::Update(step, args) => host.privileged(Privileged::Update(*step, args), secret),
        Call::Remove(step, args) => host.privileged(Privileged::Remove(*step, args), secret),
        Call::Database(command) => host.database(*command),
        Call::Logs(unit, lines) => host.logs(*unit, *lines).map(|l| l.join("\n")),
    }
}

/// What a call's result reads as: a step's `STATE<TAB>DETAIL`, or its output.
pub fn state_of(call: &Call, result: &Result<String, HostError>) -> StepState {
    match (call, result) {
        (_, Err(error)) => StepState::Failed(error.to_string()),
        (Call::Repair(_) | Call::Update(..) | Call::Remove(..), Ok(out)) => {
            StepState::parse(out.trim_end()).unwrap_or_else(|| {
                StepState::Failed(format!("unexpected helper output: {}", out.trim()))
            })
        }
        (_, Ok(out)) => StepState::Done(out.clone()),
    }
}

/// Whether the run goes on. The assistant's model is optional: its
/// download failing does not stop a repair.
pub fn goes_on(call: &Call, result: &Result<String, HostError>) -> bool {
    state_of(call, result).finished()
        || (*call == Call::Repair(Step::AssistantModel) && result.is_ok())
}

/// Runs the calls from `from` in order, reporting each; stops at the first
/// that does not go on, then runs the rescue if it covers that call (never
/// after a wrong password). `report` returning false stops it.
pub fn work_through<H: Host>(
    host: &H,
    work: &Work,
    from: usize,
    secret: &Secret,
    mut report: impl FnMut(Progress) -> bool,
) {
    for (index, call) in work.calls.iter().enumerate().skip(from) {
        let result = execute(host, call, secret);
        let on = goes_on(call, &result);
        let wrong = matches!(result, Err(HostError::WrongPassword));
        if !report(Progress { index, result }) {
            return;
        }
        if on {
            continue;
        }
        if let Some(rescue) = work.rescue.as_ref().filter(|r| !wrong && (r.from..r.to).contains(&index)) {
            for (j, call) in rescue.calls.iter().enumerate() {
                let result = execute(host, call, secret);
                if !report(Progress { index: work.calls.len() + j, result }) {
                    return;
                }
            }
        }
        return;
    }
}

pub struct Run {
    pub work: Work,
    /// Each call's state (main calls, then the rescue's) once it has run.
    pub states: Vec<Option<StepState>>,
    /// The last main call that reported.
    pub at: usize,
    pub started: Instant,
    pub ended: Option<Instant>,
    /// Wrong passwords so far; three stop the run.
    pub wrong: u8,
    rx: Option<Receiver<Progress>>,
}

impl Run {
    fn new(work: Work, now: Instant) -> Run {
        let n = work.calls.len() + work.rescue.as_ref().map_or(0, |r| r.calls.len());
        Run { work, states: vec![None; n], at: 0, started: now, ended: None, wrong: 0, rx: None }
    }

    pub fn running(&self) -> bool {
        self.ended.is_none()
    }

    /// The first main call that did not finish (the optional model aside).
    pub fn stopped_at(&self) -> Option<usize> {
        (0..self.work.calls.len()).find(|&i| {
            self.states[i].as_ref().is_some_and(|s| !s.finished())
                && self.work.calls[i] != Call::Repair(Step::AssistantModel)
        })
    }

    /// The main call running now; `None` once stopped (a rescue may run).
    pub fn current(&self) -> Option<usize> {
        if !self.running() || self.stopped_at().is_some() {
            return None;
        }
        (0..self.work.calls.len()).find(|&i| self.states[i].is_none())
    }

    pub fn ok(&self) -> bool {
        !self.running()
            && (0..self.work.calls.len()).all(|i| {
                self.states[i].as_ref().is_some_and(|s| s.finished())
                    || (self.states[i].is_some()
                        && self.work.calls[i] == Call::Repair(Step::AssistantModel))
            })
    }

    /// The `j`th rescue call's state.
    pub fn rescued(&self, j: usize) -> Option<&StepState> {
        self.states.get(self.work.calls.len() + j)?.as_ref()
    }

    /// How long it took: "2 min 41 s", "12 s".
    pub fn took(&self) -> String {
        let s = self.ended.unwrap_or_else(Instant::now).saturating_duration_since(self.started).as_secs();
        if s >= 60 { format!("{} min {} s", s / 60, s % 60) } else { format!("{s} s") }
    }

    /// Takes one result; true when the password was wrong.
    fn take(&mut self, p: Progress, now: Instant) -> bool {
        let main = self.work.calls.len();
        if p.index >= main {
            let j = p.index - main;
            let count = self.work.rescue.as_ref().map_or(0, |r| r.calls.len());
            if let Some(call) = self.work.rescue.as_ref().and_then(|r| r.calls.get(j)) {
                self.states[p.index] = Some(state_of(call, &p.result));
            }
            if j + 1 >= count {
                self.ended = Some(now);
            }
            return false;
        }
        self.at = p.index;
        if matches!(p.result, Err(HostError::WrongPassword)) {
            self.ended = Some(now);
            return true;
        }
        let call = &self.work.calls[p.index];
        let on = goes_on(call, &p.result);
        self.states[p.index] = Some(state_of(call, &p.result));
        let rescued = !on
            && self.work.rescue.as_ref().is_some_and(|r| (r.from..r.to).contains(&p.index));
        if (on && p.index + 1 == main) || (!on && !rescued) {
            self.ended = Some(now);
        }
        false
    }
}

/// The password for a run, typed in the bar.
pub struct Asking {
    pub work: Work,
    pub from: usize,
    pub prompt: PasswordPrompt,
    /// Asked again after a wrong password: the same run goes on.
    pub resume: bool,
}

impl<H: Host> App<H> {
    /// Starts `work` at `from`: the password first, unless sudo needs none
    /// (root). One action at a time; reads may run beside it.
    pub(super) fn begin(&mut self, work: Work, from: usize) {
        if !work.kind.background() && self.run.as_ref().is_some_and(Run::running) {
            self.outcome = Some((false, "Wait: other work is still running".into()));
            return;
        }
        if self.host.needs_password() {
            self.asking = Some(Asking { work, from, prompt: PasswordPrompt::default(), resume: false });
        } else {
            self.start(work, from, Secret::new(String::new()), false);
        }
    }

    /// Starts reads that need no password.
    pub(super) fn read(&mut self, work: Work) {
        self.start(work, 0, Secret::new(String::new()), false);
    }

    pub(super) fn asking_key(&mut self, key: Key) {
        let Some(mut asking) = self.asking.take() else { return };
        match asking.prompt.key(key) {
            Typed::Pending => self.asking = Some(asking),
            Typed::Cancelled if asking.resume => {
                let slot = if asking.work.kind.background() { &mut self.load } else { &mut self.run };
                if let Some(run) = slot.as_mut() {
                    run.states[asking.from] =
                        Some(StepState::Failed("no password given: nothing more was run".into()));
                }
            }
            Typed::Cancelled => {}
            Typed::Entered(secret) => self.start(asking.work, asking.from, secret, asking.resume),
        }
    }

    fn start(&mut self, work: Work, from: usize, secret: Secret, resume: bool) {
        let now = Instant::now();
        let background = work.kind.background();
        let slot = if background { &mut self.load } else { &mut self.run };
        // Try again (from > 0) and a resumed run keep the steps already done.
        let mut run = match slot.take() {
            Some(old) if old.work == work && (resume || from > 0) => old,
            _ => Run::new(work.clone(), now),
        };
        if !resume {
            run.wrong = 0;
        }
        for state in &mut run.states[from..] {
            *state = None;
        }
        run.at = from;
        run.ended = None;
        let mut again = false;
        match &self.worker {
            Some(worker) => run.rx = Some(worker(work, from, secret)),
            None => work_through(&self.host, &work, from, &secret, |p| {
                again |= run.take(p, now);
                true
            }),
        }
        *slot = Some(run);
        if again {
            self.ask_again(background);
        }
    }

    /// The password was wrong: ask again with the tries left, or stop at three.
    fn ask_again(&mut self, background: bool) {
        let slot = if background { &mut self.load } else { &mut self.run };
        let Some(run) = slot.as_mut() else { return };
        run.wrong += 1;
        if run.wrong >= 3 {
            run.states[run.at] =
                Some(StepState::Failed("three wrong passwords: nothing more was run".into()));
            return;
        }
        let mut prompt = PasswordPrompt::default();
        prompt.failures = run.wrong;
        self.asking = Some(Asking { work: run.work.clone(), from: run.at, prompt, resume: true });
    }

    /// Takes what the workers reported; quits when asked to wait for it.
    pub(super) fn poll_runs(&mut self, now: Instant) {
        for background in [false, true] {
            let slot = if background { &mut self.load } else { &mut self.run };
            let Some(run) = slot.as_mut() else { continue };
            let mut again = false;
            loop {
                let next = match &run.rx {
                    Some(rx) => rx.try_recv(),
                    None => break,
                };
                match next {
                    Ok(progress) => again |= run.take(progress, now),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        run.rx = None;
                        if run.running() {
                            let at = run.at;
                            run.states[at].get_or_insert_with(|| {
                                StepState::Failed("the work stopped unexpectedly".into())
                            });
                            run.ended = Some(now);
                        }
                    }
                }
            }
            if again {
                self.ask_again(background);
            }
        }
        if self.quit_when_done && !self.run.as_ref().is_some_and(Run::running) {
            self.quit = true;
        }
    }

    /// Ctrl+C: while work runs, as `q` (it asks); a second one quits at once.
    pub fn interrupt(&mut self) {
        let running = self.run.as_ref().is_some_and(Run::running);
        if running && !matches!(self.question, Some((Question::Quit, _))) {
            self.question = Some((Question::Quit, true));
        } else {
            self.quit = true;
        }
    }

    /// Home's note on the current or last action.
    pub(super) fn work_note(&self) -> Option<Vec<Span<'static>>> {
        let run = self.run.as_ref()?;
        let t = &self.theme;
        Some(if run.running() {
            vec![
                Span::styled(SPINNER[self.tick_count % SPINNER.len()], t.teal()),
                Span::raw(format!(" {}…", run.work.kind.doing())),
            ]
        } else if run.ok() {
            vec![Span::styled("✓", t.green()), Span::raw(format!(" {}", run.work.kind.done()))]
        } else {
            vec![
                Span::styled("✗", t.red()),
                Span::raw(format!(" {} · see Maintenance", run.work.kind.stopped())),
            ]
        })
    }
}
```

- [ ] **Step 5: Wire it in**

`app.rs`:
- Add the fields, and initialise them in `lazy`:
  - `run: None,`
  - `load: None,`
  - `asking: None,`
  - `worker: None,`
  - `quit_when_done: false,`

  ```rust
      /// The current or last action (Update, Back up, Fix, Uninstall): Home
      /// shows it; Quit waits for it.
      pub run: Option<super::run::Run>,
      /// The current or last read (Repair's check, the Database report).
      pub load: Option<super::run::Run>,
      /// The password for a run, typed in the bar.
      pub asking: Option<super::run::Asking>,
      /// Runs work on another thread (`run` sets it; tests leave it out).
      pub worker: Option<super::run::Worker>,
      /// Yes to "Quit when it is done?".
      pub quit_when_done: bool,
  ```

- In `key()`, after `if self.question.is_some() { return self.question_key(key); }`, add:

  ```rust
          if self.asking.is_some() {
              return self.asking_key(key);
          }
  ```

- In `tick()`, after `self.poll(now);`, add `self.poll_runs(now);`.

`work.rs`:
- `quit_or_ask`: replace its condition with `if self.pending.is_some() || self.run.as_ref().is_some_and(super::run::Run::running)`.
- In `question_key`, replace the `Question::Quit => self.quit = true,` arm with:

  ```rust
              Question::Quit if self.run.as_ref().is_some_and(super::run::Run::running) => {
                  self.quit_when_done = true;
              }
              Question::Quit => self.quit = true,
  ```

- In `bar()`'s question match, put this arm before the existing `Question::Quit` arm:

  ```rust
                  Question::Quit if self.run.as_ref().is_some_and(super::run::Run::running) => (
                      "Quit when it is done?".to_owned(),
                      "the work finishes first".to_owned(),
                  ),
  ```

- In `bar()`, after the question block, add:

  ```rust
          if let Some(asking) = &self.asking {
              let failures = asking.prompt.failures;
              return Bar::Typing {
                  note: (failures > 0).then(|| format!("Wrong password, {} tries left.", 3 - failures)),
                  label: "Your password (sudo)".into(),
                  shown: asking.prompt.masked(),
                  done: asking.work.kind.verb().into(),
              };
          }
          if self.quit_when_done && let Some(run) = &self.run {
              return Bar::Busy {
                  text: format!("Quits when it is done · {}…", run.work.kind.doing()),
                  tick: self.tick_count,
              };
          }
  ```

`home.rs` `draw`: replace `let mut lines = vec![app.status_line()];` with:

```rust
    let mut status = app.status_line();
    if let Some(note) = app.work_note() {
        status.spans.push(Span::raw("   "));
        status.spans.extend(note);
    }
    let mut lines = vec![status];
```

`mod.rs`:
- Add `mod run;`, `#[cfg(test)] mod run_tests;` and `#[cfg(test)] mod script_host;`.
- In `run()`, after `app.health = Some(health);`, add:

  ```rust
      // Helper steps run on their own thread with their own host: the
      // screen keeps drawing while dnf or a backup takes minutes.
      app.worker = Some(Box::new(|work, from, secret| {
          let (send, receive) = std::sync::mpsc::channel();
          std::thread::spawn(move || {
              let host = Native { runner: SystemRunner };
              run::work_through(&host, &work, from, &secret, |p| send.send(p).is_ok());
          });
          receive
      }));
  ```

- Replace the Ctrl+C arm's body `app.quit = true; continue;` with `app.interrupt(); continue;`.

- [ ] **Step 6: Run the tests**

Run: `cargo test -p openvibes-admin`
Expected: PASS (the new `run_tests`, and every old test).

- [ ] **Step 7: Docs and commit**

In `docs/components/openvibes-admin.md` ("Administration TUI"), add a paragraph after the Help paragraph:

> **Work in the background**: helper steps (Update, Back up, Repair, Uninstall) run on their own thread, so the screen keeps drawing. The password is asked in the bar ("Your password (sudo)"; root is not asked), handed to that thread and dropped when the work ends. A wrong password is said in the bar with the tries left; after three, nothing more runs. Home's status line shows the running work, then its result. `q` (or Ctrl+C) while work runs asks "Quit when it is done?": Yes quits once it has finished, and a second Ctrl+C quits at once. Tests: `src/tui/run_tests.rs`.

```bash
git add crates/openvibes-admin/src/tui docs/components/openvibes-admin.md
git commit -m "TUI: run helper steps on a worker thread, password in the bar, quit waits for work"
```

---

### Task 3: The Maintenance menu and the Database report

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/mod.rs` and `crates/openvibes-admin/src/tui/maint/database.rs`.
- Modify: `crates/openvibes-admin/src/tui/nav.rs`:
  - `Screen::Maint(Page)`.
  - Its header and render arms.
  - The legacy Setup label becomes "Components and ports".
  - Remove the `Tab::Database` arms.
- Modify: `crates/openvibes-admin/src/tui/home.rs`:
  - Delete `MAINTENANCE`, `draw_maintenance` and `maintenance_key`.
  - Home's Maintenance description becomes "updates, repair, database, backup, uninstall".
  - `name()` and `here()` get `Screen::Maint(page)` arms.
- Modify: `crates/openvibes-admin/src/tui/app.rs`:
  - Field `maint: Maint`.
  - `Screen::Maintenance` routes to `menu_key` and `Screen::Maint(page)` to `maint_key`.
  - Delete `Tab::Database` and its `open` and `legacy_dispatch` arms.
- Modify: `crates/openvibes-admin/src/tui/mod.rs`:
  - `mod maint;`.
  - Remove `mod database_view;` and the `Tab::Database` arm of `legacy_view`.
- Modify: `crates/openvibes-admin/src/tui/database.rs`:
  - Delete `status`, `confirm`, `open_database`, `load_database` and `database_key`.
  - The module doc becomes "The health checks Status shows (admin TUI spec §5)…".
- Delete: `crates/openvibes-admin/src/tui/database_view.rs`.
- Modify: `crates/openvibes-admin/src/tui/database_tests.rs`: delete `database_shows_the_status_and_migrates_only_after_yes` and `a_refused_database_command_names_the_group`.
- Modify: `crates/openvibes-admin/src/tui/nav_tests.rs`:
  - Delete `esc_answers_the_database_question_no`.
  - In `no_legacy_screen_advertises_tab_and_q_only_on_the_fresh_install_form`, the loop goes over `[Tab::Setup, Tab::Configuration]`.
  - In `maintenance_reaches_todays_screens_and_esc_comes_back` and `esc_with_unsaved_settings_asks_and_yes_goes_back_to_maintenance`, replace the `app.key(Key::Down)` before the second `Enter` with `app.nav.row = super::maint::row_of("Settings files");`.
- Modify: `crates/platform-host/src/lib.rs` (delete `Database::Migrate` and `Database::Maintenance`) and `crates/platform-host/src/native.rs` (delete the journal branch in `database`).
- Modify: `crates/platform-host/tests/native.rs`:
  - The test `database_commands_run_the_cli_as_its_account_and_changes_are_journalled` is renamed `database_commands_run_the_cli_as_its_account`.
  - It keeps the `status` part, and its `migrate` part goes: the answer list, the assert, and `calls.len() == 3` becomes `calls.len() == 1`.
- Modify: `crates/openvibes-admin/src/tui/tests.rs`: delete the `Database::Migrate` and `Database::Maintenance` arms of the fake.
- Modify: `crates/openvibes-admin/src/helper.rs`: `journal_units`, so that the maintenance timer's log includes its service.

**Interfaces:**
- Consumes: `run::{Call, Kind, Work}`, `App::read` (Task 2) and `Bar::act` (Task 1).
- Produces:
  - `pub enum Page { Database }`, with `title()` and `help()` (later tasks add variants).
  - `pub struct Maint { pub disk: Option<DiskUse> }` (later tasks add fields), `#[derive(Default)]`.
  - `maint::draw_menu`, `maint::draw(frame, head, app, page)`.
  - `App::menu_key`, `App::open_page(page)` and `App::maint_key(page, key)`.
  - `#[cfg(test)] pub fn row_of(name: &str) -> usize`.
  - In `maint/mod.rs`: `pub fn human(bytes: u64) -> String`, `pub fn info(name: &str, value: Vec<Span<'static>>) -> Line<'static>` and `pub fn failure(theme: &Theme, why: &str, todo: &str) -> Vec<Line<'static>>`.
  - In `maint/database.rs`: `pub fn work() -> Work`, `pub fn last_cleanup(journal: &str) -> Option<(String, String)>` and `pub fn rows(status: Result<&str, &str>, journal: Option<&str>, disk: Option<&DiskUse>) -> Vec<(&'static str, String)>`.
  - `status::wrap` becomes `pub(super)`.

- [ ] **Step 1: Write the failing tests**

At the bottom of `maint/database.rs`:

```rust
#[cfg(test)]
mod tests {
    use platform_host::{Database, DiskUse};

    use super::{last_cleanup, rows};
    use crate::tui::{
        app::Key,
        maint::{Page, human, row_of},
        nav::Screen,
        tests::{app, screen},
    };

    #[test]
    fn the_database_page_is_a_report_with_no_actions() {
        let mut app = app(false);
        app.key(Key::Down);
        app.key(Key::Enter);
        app.nav.row = row_of("Database");
        app.key(Key::Enter);
        assert_eq!(app.nav.screen, Screen::Maint(Page::Database));
        let text = screen(&app, 80, 24);
        for want in [
            "Maintenance › Database",
            "25 · up to date",
            "42 MB · disk 40% used, 20G free",
            "90 days of findings",
            "automatic, every night · not run yet",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
        assert!(!text.contains("Move") && !text.contains("igrate"), "a report: no actions\n{text}");
        assert_eq!(*app.host.database_calls.borrow(), [Database::Status]);
    }

    #[test]
    fn the_last_clean_up_is_read_from_its_journal() {
        let journal = "2026-10-11T00:41:02+02:00 limebox openvibes-admin[4242]: created 1 partitions, dropped 1, deleted 12 expired audit events\n\
                       2026-10-11T00:41:02+02:00 limebox openvibes-admin[4242]: recorded history for 8 hosts, deleted 0 old rows";
        assert_eq!(
            last_cleanup(journal),
            Some(("2026-10-11 00:41".to_owned(), "1 day of findings, 12 audit events".to_owned()))
        );
        assert_eq!(last_cleanup("Started openvibes-maintenance.timer"), None);
    }

    #[test]
    fn an_unreachable_database_says_why_and_sizes_read_well() {
        let rows = rows(Err("failed: database unavailable"), None, None);
        assert_eq!(rows[0], ("Database", "failed: database unavailable".to_owned()));
        let disk = DiskUse { path: "/var/lib/pgsql".into(), used_percent: 41, available: "70G".into() };
        let ok = super::rows(Ok("schema version 46\ndatabase size 3174 MiB\n"), None, Some(&disk));
        assert_eq!(ok[1], ("Size", "3.1 GB · disk 41% used, 70G free".to_owned()));
        assert_eq!(human(42 * 1024 * 1024), "42 MB");
        assert_eq!(human(431), "1 KB");
    }
}
```

In `helper.rs`, add (or extend) a test module:

```rust
#[cfg(test)]
mod journal_tests {
    use platform_host::Unit;

    #[test]
    fn the_timer_and_socket_logs_include_their_services() {
        assert_eq!(
            super::journal_units(Unit::Maintenance),
            ["openvibes-maintenance.timer", "openvibes-maintenance.service"]
        );
        assert_eq!(super::journal_units(Unit::Ingest), ["openvibes-ingest.service"]);
        assert_eq!(super::journal_units(Unit::Llm).len(), 3);
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin maint:: journal_tests`
Expected: FAIL to compile (`maint`, `journal_units` missing).

- [ ] **Step 3: Implement `maint/mod.rs`**

```rust
//! Maintenance (spec §6): the menu and the pages behind it, on today's
//! backend. Pages whose backend comes with a later step are not listed
//! until then; today's Components and ports and Settings files screens
//! stay behind the menu until their pages replace them.

mod database;

use platform_host::{DiskUse, Host};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    app::{App, Key, Tab},
    nav::Screen,
    status::wrap,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
        theme::Theme,
    },
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Page {
    Database,
}

impl Page {
    pub fn title(self) -> &'static str {
        match self {
            Page::Database => "Database",
        }
    }
    /// What the keys do here, for Help.
    pub fn help(self) -> &'static str {
        match self {
            Page::Database => "A report: the clean-up runs by itself every night.",
        }
    }
}

/// What the pages keep while open.
#[derive(Default)]
pub struct Maint {
    /// The database's disk, read when Database opens.
    pub disk: Option<DiskUse>,
}

#[derive(Clone, Copy)]
enum Entry {
    Page(Page),
    Legacy(Tab),
}

/// The menu, in spec §3's order; later tasks add their pages.
const ENTRIES: [(Entry, &str); 3] = [
    (Entry::Legacy(Tab::Setup), "Components and ports"),
    (Entry::Page(Page::Database), "Database"),
    (Entry::Legacy(Tab::Configuration), "Settings files"),
];

fn value(entry: Entry) -> &'static str {
    match entry {
        Entry::Legacy(Tab::Setup) => "agent, assistant, ports (the previous screen)",
        Entry::Legacy(Tab::Configuration) => "feeds, proxy, limits, database connection",
        Entry::Page(Page::Database) => "schema, size, automatic clean-up",
    }
}

/// The menu row of `name` (tests).
#[cfg(test)]
pub fn row_of(name: &str) -> usize {
    ENTRIES.iter().position(|(_, n)| *n == name).expect("a Maintenance entry")
}

/// "3.1 GB", "42 MB", "1 KB".
pub fn human(bytes: u64) -> String {
    let mb = bytes as f64 / (1024.0 * 1024.0);
    if mb >= 1024.0 {
        format!("{:.1} GB", mb / 1024.0)
    } else if mb >= 1.0 {
        format!("{mb:.0} MB")
    } else {
        format!("{} KB", bytes.div_ceil(1024))
    }
}

/// An information row in the pages' value column (26 wide, maint3.py).
pub fn info(name: &str, value: Vec<Span<'static>>) -> Line<'static> {
    let mut spans = vec![Span::raw(format!("    {name:<26} "))];
    spans.extend(value);
    Line::from(spans)
}

/// A failed step (spec §2 "Errors"): what failed and why in red, what to
/// do and what was left as it was, dim.
pub fn failure(theme: &Theme, why: &str, todo: &str) -> Vec<Line<'static>> {
    let mut out: Vec<Line<'static>> = wrap(why, 72, 2)
        .into_iter()
        .map(|l| Line::styled(format!("    {l}"), theme.red()))
        .collect();
    out.extend(wrap(todo, 72, 2).into_iter().map(|l| Line::styled(format!("    {l}"), theme.dim())));
    out
}

pub fn draw_menu<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let bar = app.bar(Bar::keys(&[("Enter", "Open")]));
    let area = frame::draw(frame, &app.theme, head, Some("Maintenance"), &bar);
    let rows: Vec<Row> = ENTRIES.iter().map(|(e, name)| Row::entry(name, value(*e))).collect();
    let mut scroll = app.nav.scroll.get();
    let lines = list::lines(&app.theme, &rows, app.nav.row, &mut scroll, area.height, 22);
    app.nav.scroll.set(scroll);
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, page: Page) {
    match page {
        Page::Database => database::draw(frame, head, app),
    }
}

impl<H: Host> App<H> {
    pub(super) fn menu_key(&mut self, key: Key) {
        if self.move_row(key, ENTRIES.len()) || key != Key::Enter {
            return;
        }
        match ENTRIES[self.nav.row].0 {
            Entry::Legacy(tab) => self.open(tab),
            Entry::Page(page) => self.open_page(page),
        }
    }

    pub(super) fn open_page(&mut self, page: Page) {
        self.message = None;
        self.nav.go(Screen::Maint(page));
        match page {
            Page::Database => {
                self.maint.disk = self
                    .host
                    .disk()
                    .ok()
                    .and_then(|d| d.into_iter().find(|d| d.path == "/var/lib/pgsql"));
                self.read(database::work());
            }
        }
    }

    pub(super) fn maint_key(&mut self, page: Page, key: Key) {
        // Database is a report: it has no keys of its own.
        let _ = (page, key);
    }
}
```

`maint/database.rs`:

```rust
//! Maintenance › Database (spec §6, maint3.py): a report only. Migrations
//! run in Update, and the clean-up runs by itself every night (the
//! maintenance timer), so neither has a button (spec §1.5).

use platform_host::{Database, DiskUse, Host, StepState, Unit};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{human, info};
use crate::tui::{
    app::App,
    run::{Call, Kind, Work},
    ui::{
        bar::{Bar, SPINNER},
        frame,
        logo::Header,
    },
};

/// What the nightly clean-up keeps: `maintenance`'s default, which the
/// timer runs with.
const KEPT: &str = "90 days of findings";

pub fn work() -> Work {
    Work::new(Kind::Report, vec![Call::Database(Database::Status), Call::Logs(Unit::Maintenance, 50)])
}

fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines().find_map(|l| l.strip_prefix(name)).map(str::trim)
}

/// The last clean-up in its journal: when, and what it removed.
pub fn last_cleanup(journal: &str) -> Option<(String, String)> {
    let line = journal.lines().rev().find(|l| l.contains("partitions, dropped "))?;
    let stamp = line.split_whitespace().next()?.replacen('T', " ", 1);
    let when = stamp.get(..16).unwrap_or(&stamp).to_owned();
    let number = |after: &str| {
        let rest = line.split(after).nth(1)?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty()).then_some(digits)
    };
    let days = number("dropped ")?;
    let audit = number("deleted ").unwrap_or_else(|| "0".into());
    let unit = if days == "1" { "day" } else { "days" };
    Some((when, format!("{days} {unit} of findings, {audit} audit events")))
}

pub fn rows(
    status: Result<&str, &str>,
    journal: Option<&str>,
    disk: Option<&DiskUse>,
) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    match status {
        Ok(text) => {
            let schema = field(text, "schema version").map_or("unknown".to_owned(), |v| format!("{v} · up to date"));
            rows.push(("Schema", schema));
            let mut size = field(text, "database size")
                .and_then(|s| s.trim_end_matches("MiB").trim().parse::<u64>().ok())
                .map_or("unknown".to_owned(), |mib| human(mib * 1024 * 1024));
            if let Some(d) = disk {
                size.push_str(&format!(" · disk {}% used, {} free", d.used_percent, d.available));
            }
            rows.push(("Size", size));
        }
        Err(error) => rows.push(("Database", error.to_owned())),
    }
    rows.push(("Data kept", KEPT.to_owned()));
    match journal.and_then(last_cleanup) {
        Some((when, removed)) => {
            rows.push(("Clean-up", format!("automatic, every night · last run {when}")));
            rows.push(("Removed last run", removed));
        }
        None => rows.push(("Clean-up", "automatic, every night · not run yet".to_owned())),
    }
    rows
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let area = frame::draw(frame, t, head, Some("Database"), &app.bar(Bar::act(&[])));
    let mut lines = vec![Line::raw("")];
    match app.load.as_ref().filter(|r| r.work.kind == Kind::Report && !r.running()) {
        Some(run) => {
            let status = match &run.states[0] {
                Some(StepState::Done(text)) => Ok(text.as_str()),
                Some(other) => Err(other.detail()),
                None => Err("not read"),
            };
            let journal = match run.states.get(1) {
                Some(Some(StepState::Done(text))) => Some(text.as_str()),
                _ => None,
            };
            for (name, value) in rows(status, journal, app.maint.disk.as_ref()) {
                let style = if name == "Database" { t.red() } else { ratatui::style::Style::new() };
                lines.push(info(name, vec![Span::styled(value, style)]));
            }
        }
        None => lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(SPINNER[app.tick_count % SPINNER.len()], t.teal()),
            Span::raw(" Reading the database…"),
        ])),
    }
    frame.render_widget(Paragraph::new(lines), area);
}
```

Wiring:
- `nav.rs`:
  - `Screen` gets `Maint(super::maint::Page),`.
  - In `header`, add `Screen::Maint(page) => format!(" · Maintenance › {}", page.title()),`; the legacy `Tab::Setup` label becomes `" · Maintenance › Components and ports"`, and the `_ => " · Maintenance › Database"` arm is deleted (the match has two tabs now).
  - In `render`, replace `Screen::Maintenance => home::draw_maintenance(…)` with `Screen::Maintenance => super::maint::draw_menu(frame, &head, app),` and add `Screen::Maint(page) => super::maint::draw(frame, &head, app, *page),`.
  - Delete the `Tab::Database` arms of `legacy_at_rest` and `typing`.
- `app.rs`:
  - Add `pub maint: super::maint::Maint,` (initialised `Default::default()`).
  - In `key()`'s screen match, `Screen::Maintenance => self.menu_key(key),`, and add `Screen::Maint(page) => self.maint_key(page, key),`.
  - Delete `Tab::Database` from `enum Tab`, `open` and `legacy_dispatch`.
- `home.rs`:
  - Delete the Maintenance items, as listed under **Files**.
  - In `home_key`, `1 => self.nav.go(Screen::Maintenance)` stays.
  - `name()`: add `Screen::Maint(page) => page.title().into(),`. `here()`: add `Screen::Maint(page) => page.help(),`.
- `status.rs`: `fn wrap` becomes `pub(super) fn wrap`.
- `helper.rs`:

  ```rust
  /// The journal units of `unit`: the socket and the timer say little;
  /// their services say why.
  fn journal_units(unit: Unit) -> Vec<&'static str> {
      match unit {
          Unit::Llm => vec![unit.name(), "openvibes-llm.service", "openvibes-llm-proxy.service"],
          Unit::Maintenance => vec![unit.name(), "openvibes-maintenance.service"],
          _ => vec![unit.name()],
      }
  }
  ```

  In `logs`, replace `journalctl.args(["-u", unit.name()]);` and the `if unit == Unit::Llm { … }` block with `for name in journal_units(unit) { journalctl.args(["-u", name]); }`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin && cargo test -p platform-host`
Expected: PASS.

- [ ] **Step 5: Docs and commit**

In `docs/components/openvibes-admin.md`:
- The sentence "Maintenance (interim, until it is reworked) holds today's Setup, Settings files (Configuration) and Database screens: …" becomes:

  > Maintenance lists Components and ports (today's Setup screen, until Optional parts and Ports replace it), Database and Settings files (today's Configuration screen, until the console's admin pages hold its fields, spec §12 step 6); later entries are added by their pages. Today's screens keep their own keys, and `Esc` leaves them only when nothing is being typed or asked (unsaved settings ask first).

- The "**Database**:" paragraph becomes:

  > **Database** (Maintenance › Database): a report only (spec §6). It shows the schema ("up to date"), the database size with its disk's use and free space, the data kept (90 days of findings, the timer's default), and the automatic nightly clean-up with its last run and what it removed. These are read on another thread from `status` (run as `openvibes-admin`) and from the maintenance service's journal (`helper logs` now reads `openvibes-maintenance.service` along with the timer). Migrations run in Update; the clean-up has no button.

```bash
git add -A crates/openvibes-admin crates/platform-host docs/components/openvibes-admin.md
git commit -m "TUI: Maintenance menu and the Database report; drop the old Database screen"
```

---

### Task 4: Backups — unique names, a folder checked as typed, the choice remembered by the helper

**Files:**
- Modify: `crates/openvibes-admin/src/setup/backup.rs`: `MEMORY` and `remember`; `dump` remembers the folder.
- Modify: `crates/openvibes-admin/src/setup/mod.rs`: `mod backup;` becomes `pub(crate) mod backup;`, and the `RemoveArgs` literal in `uninstall_all` gets `remember_choice: false`.
- Modify: `crates/openvibes-admin/src/setup/update.rs` and `crates/openvibes-admin/src/setup/remove.rs`:
  - `remember_choice` in both args types.
  - The Backup step records the choice.
  - Every `UpdateArgs { … }` and `RemoveArgs { … }` literal (`grep -rn 'UpdateArgs {\|RemoveArgs {' crates/openvibes-admin/src`; in `remove_tests.rs`, the `args` helper) gets `remember_choice: false`.
- Modify: `crates/openvibes-admin/src/main.rs`: the `UpdateArgs` literal at `setup --update` gets `remember_choice: false`.
- Modify: `crates/platform-host/src/lib.rs` (`Host::free_space`) and `crates/platform-host/src/native.rs` (its `df`).
- Create: `crates/openvibes-admin/src/tui/maint/backup.rs` (this task: `Memory`, `file_stem`, `free_path` and `check_folder`).
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs` (`pub mod backup;`) and `crates/openvibes-admin/src/tui/setup.rs` (`free_root_key` calls `free_path`).

**Interfaces:**
- Produces:
  - Backend:
    - `pub const MEMORY: &str = "/etc/openvibes/backup.toml"`.
    - `pub fn remember<R: Runner>(ctx: &Ctx<R>, folder: Option<&Path>, first: Option<bool>) -> Result<(), String>`.
    - `UpdateArgs::remember_choice: bool` and `RemoveArgs::remember_choice: bool` (`--remember-choice`).
    - `Host::free_space(&self, path: &str) -> Option<String>` (default `None`).
  - TUI:
    - `pub struct Memory { pub folder: Option<String>, pub first: bool }`, with `Memory::parse(&str)` and `Memory::load(root: &Path)`.
    - `pub fn file_stem(version: &str, now: chrono::NaiveDateTime) -> String`.
    - `pub fn free_path(base: &str, ext: &str, exists: impl Fn(&str) -> bool) -> String`.
    - `pub fn check_folder<H: Host>(host: &H, text: &str) -> Result<String, String>`.

- [ ] **Step 1: Write the failing tests**

In `setup/backup.rs` `mod tests` (it already has `postgres(&fake)`):

```rust
    #[test]
    fn a_backup_remembers_its_folder_and_the_choice_only_when_asked() {
        let fake = Fake::new("backup-memory");
        postgres(&fake);
        std::fs::create_dir_all(fake.root.join("home/alice")).unwrap();
        let plan = plan(&[Ingest]);
        super::dump(&fake.ctx(&plan), std::path::Path::new("/home/alice/b.dump")).unwrap();
        assert_eq!(fake.text(super::MEMORY), "folder = \"/home/alice\"\n");
        let args = crate::setup::update::UpdateArgs { remember_choice: true, ..Default::default() };
        let state = crate::setup::update::run(&fake.ctx(&plan), platform_host::UpdateStep::Backup, &args);
        assert!(matches!(state, platform_host::StepState::Skipped(_)), "{state:?}");
        let text = fake.text(super::MEMORY);
        assert!(text.contains("folder = \"/home/alice\"") && text.contains("first = false"), "{text}");
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(fake.root.join("etc/openvibes/backup.toml")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "the TUI reads it as the operator");
    }
```

At the bottom of `tui/maint/backup.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::{Memory, check_folder, file_stem, free_path};
    use crate::tui::tests::app;

    #[test]
    fn names_carry_the_version_date_and_time() {
        let at = chrono::NaiveDate::from_ymd_opt(2026, 10, 10).unwrap().and_hms_opt(20, 41, 7).unwrap();
        assert_eq!(file_stem("0.2.9", at), "openvibes-0.2.9-2026-10-10-2041");
    }

    #[test]
    fn a_second_backup_in_the_same_minute_gets_its_own_name() {
        let taken = ["/b/x.dump", "/b/x-2.dump"];
        assert_eq!(free_path("/b/x", "dump", |p| taken.contains(&p)), "/b/x-3.dump");
        assert_eq!(free_path("/b/x", "dump", |_| false), "/b/x.dump");
    }

    #[test]
    fn the_memory_is_empty_until_the_helper_writes_it() {
        assert_eq!(Memory::parse(""), Memory::default());
        assert_eq!(
            Memory::parse("folder = \"/mnt/nas/openvibes\"\nfirst = true\n"),
            Memory { folder: Some("/mnt/nas/openvibes".into()), first: true }
        );
        assert_eq!(Memory::load(std::path::Path::new("/nonexistent")), Memory::default());
    }

    #[test]
    fn the_folder_is_checked_as_typed() {
        let app = app(false);
        let dir = std::env::temp_dir().join(format!("ov-folder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a-file");
        std::fs::write(&file, "x").unwrap();
        let shown = dir.display().to_string();
        assert_eq!(check_folder(&app.host, ""), Err("type a folder, or Tab to browse".into()));
        assert_eq!(check_folder(&app.host, "backups"), Err("a full path, starting with /".into()));
        assert!(check_folder(&app.host, &format!("{shown}/nope")).unwrap_err().ends_with("does not exist"));
        assert!(check_folder(&app.host, &file.display().to_string()).unwrap_err().ends_with("is not a folder"));
        assert_eq!(check_folder(&app.host, &shown), Ok(format!("{shown} exists and is writable")));
        assert!(std::fs::read_dir(&dir).unwrap().count() == 1, "the probe is gone");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
```

In `crates/platform-host/tests/native.rs`:

```rust
#[test]
fn free_space_is_dfs_avail_column() {
    let host = fake(vec![(vec!["/usr/bin/df"], out(0, " Avail\n  1.8T\n", ""))]);
    assert_eq!(host.free_space("/mnt/nas"), Some("1.8T".into()));
    let calls = host.runner.calls.borrow();
    assert_eq!(calls[0], ["/usr/bin/df", "--output=avail", "-h", "--", "/mnt/nas"]);
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin backup && cargo test -p platform-host free_space`
Expected: FAIL to compile.

- [ ] **Step 3: Implement the backend**

`setup/backup.rs`:

```rust
/// The TUI's backup choices (world-readable: one folder, one flag);
/// Remove everything deletes it with /etc/openvibes.
pub const MEMORY: &str = "/etc/openvibes/backup.toml";

/// Records the folder of a backup just written and, when given, whether
/// the operator backs up first (Update's and Uninstall's Back up first).
pub fn remember<R: Runner>(ctx: &Ctx<R>, folder: Option<&Path>, first: Option<bool>) -> Result<(), String> {
    let mut doc: toml_edit::DocumentMut =
        ctx.read(MEMORY).unwrap_or_default().parse().unwrap_or_default();
    if let Some(folder) = folder.and_then(Path::to_str) {
        doc["folder"] = toml_edit::value(folder);
    }
    if let Some(first) = first {
        doc["first"] = toml_edit::value(first);
    }
    ctx.put(MEMORY, doc.to_string().as_bytes(), None, 0o644)
}
```

In `dump`, after `ctx.write_new(&roles_file, …)?;`, add:

```rust
        // A convenience for the next time: a failure here never fails the backup.
        let kept = match remember(ctx, out.parent(), None) {
            Ok(()) => String::new(),
            Err(error) => format!(" (the folder is not remembered: {error})"),
        };
```

Then the `format!` ends with `{note}{kept}`.

In both `UpdateArgs` and `RemoveArgs`:

```rust
    /// Record in backup.toml whether this run backs up first (the TUI's
    /// Back up first, remembered for next time).
    #[arg(long)]
    pub remember_choice: bool,
```

In `update::run`, the `UpdateStep::Backup` arm becomes:

```rust
        UpdateStep::Backup => {
            if args.remember_choice {
                // ponytail: best effort; the choice only presets a checkbox.
                let _ = backup::remember(ctx, None, Some(args.backup.is_some()));
            }
            match &args.backup {
                None => Ok(StepState::Skipped("no backup chosen".into())),
                Some(path) => backup::dump(ctx, path).map(StepState::Done),
            }
        }
```

In `remove::run`, `RemoveStep::Backup` gets the same.

`platform-host/src/lib.rs`, in `trait Host`, after `disk`:

```rust
    /// Space left on the file system holding `path`, as `df -h` writes it;
    /// `None` when unknown (the backup folder's check).
    fn free_space(&self, path: &str) -> Option<String> {
        let _ = path;
        None
    }
```

In `native.rs`'s `impl Host`:

```rust
    fn free_space(&self, path: &str) -> Option<String> {
        let out = self.run(Df, &["--output=avail", "-h", "--", path]).ok()?;
        (out.status == 0).then(|| out.stdout.lines().nth(1).map(|l| l.trim().to_owned())).flatten()
    }
```

- [ ] **Step 4: Implement the TUI side** (`tui/maint/backup.rs`)

```rust
//! Backups (spec §6, §10.1, approved.md 37–38): a folder you choose and
//! the helper remembers; a new file name every time; Back up first off
//! by default, then your last choice.

use std::path::Path;

use platform_host::Host;

use crate::setup::backup::MEMORY;

/// What the helper remembered (`/etc/openvibes/backup.toml`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Memory {
    pub folder: Option<String>,
    pub first: bool,
}

impl Memory {
    pub fn parse(text: &str) -> Memory {
        let table: toml::Table = text.parse().unwrap_or_default();
        Memory {
            folder: table.get("folder").and_then(toml::Value::as_str).map(str::to_owned),
            first: table.get("first").and_then(toml::Value::as_bool).unwrap_or(false),
        }
    }
    /// From under `root` (`/` on a host; a temporary folder in tests).
    pub fn load(root: &Path) -> Memory {
        std::fs::read_to_string(root.join(MEMORY.trim_start_matches('/')))
            .map(|text| Memory::parse(&text))
            .unwrap_or_default()
    }
}

/// `openvibes-<version>-<date>-<HHMM>`: the version the dump's data belongs to.
pub fn file_stem(version: &str, now: chrono::NaiveDateTime) -> String {
    format!("openvibes-{version}-{}", now.format("%Y-%m-%d-%H%M"))
}

/// `base.ext`, or `base-2.ext`, `base-3.ext`… when taken.
pub fn free_path(base: &str, ext: &str, exists: impl Fn(&str) -> bool) -> String {
    std::iter::once(format!("{base}.{ext}"))
        .chain((2..).map(|n| format!("{base}-{n}.{ext}")))
        .find(|path| !exists(path))
        .unwrap_or_default()
}

/// The folder as typed (spec §2): a full path to a folder you can write
/// to, with its free space; or what is wrong.
pub fn check_folder<H: Host>(host: &H, text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("type a folder, or Tab to browse".into());
    }
    let path = Path::new(text);
    if !path.is_absolute() {
        return Err("a full path, starting with /".into());
    }
    match std::fs::metadata(path) {
        Err(_) => return Err(format!("{text} does not exist")),
        Ok(meta) if !meta.is_dir() => return Err(format!("{text} is not a folder")),
        Ok(_) => {}
    }
    // ponytail: a probe file made and removed at once (access(2) needs
    // unsafe). A root-squashed NFS folder passes here though the helper,
    // as root, cannot write there: its backup step then says so.
    let probe = path.join(format!(".openvibes-write-check-{}", std::process::id()));
    match std::fs::OpenOptions::new().write(true).create_new(true).open(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(&probe);
        }
        Err(_) => return Err(format!("{text} is not writable for you")),
    }
    Ok(match host.free_space(text) {
        Some(free) => format!("{text} exists and is writable · {free} free"),
        None => format!("{text} exists and is writable"),
    })
}
```

In `tui/setup.rs`, `free_root_key`'s body becomes:

```rust
    super::maint::backup::free_path(&format!("{home}/openvibes-root-ca"), "key", exists)
```

Its existing test `the_default_root_key_name_skips_taken_files` still holds.

- [ ] **Step 5: Run the tests**

Run: `cargo test -p openvibes-admin && cargo test -p platform-host`
Expected: PASS.

- [ ] **Step 6: Docs and commit**

In `docs/components/openvibes-admin.md` ("Setup command"):
- The Backups bullet gains: "The folder of every backup written is remembered in `/etc/openvibes/backup.toml` (0644: the folder and `first`), and `--remember-choice` (Update and Uninstall from the TUI) also records whether the run backed up first; Remove everything deletes it with `/etc/openvibes`."
- The verb list gains `[--remember-choice]` on `update-step` and `remove-step`.

```bash
git add -A crates/openvibes-admin crates/platform-host docs/components/openvibes-admin.md
git commit -m "Backups: unique names, folder check, the helper remembers folder and choice"
```

---

### Task 5: The folder field, the folder browser, and Maintenance › Back up

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/folder.rs`, `crates/openvibes-admin/src/tui/maint/backup_tests.rs`.
- Modify: `crates/openvibes-admin/src/tui/maint/backup.rs` (the page: `draw` and `App::backup_key`).
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs`:
  - `Page::Backup` and `Page::Folder`.
  - `Maint` fields `memory`, `first`, `folder` and `browse`.
  - The menu entry "Back up", and its routing.
  - `editing()`.
- Modify: `crates/openvibes-admin/src/tui/app.rs`:
  - Field `pub root: PathBuf` (`/`).
  - `key()` routes keys to the page while a value is typed there.
- Modify: `crates/openvibes-admin/src/tui/script_host.rs` and `crates/openvibes-admin/src/tui/tests.rs`: `app()` sets `root` to a fresh temporary folder, so that no test reads the host's own files.

**Interfaces:**
- Consumes: `Memory`, `check_folder`, `free_path` and `file_stem` (Task 4); `Bar::edit` (Task 1); `App::begin` and `Kind::Backup` (Task 2).
- Produces:
  - `pub struct Folder { pub text: String, pub check: Option<Result<String, String>>, before: Option<String> }`, with `editing()`, `edit()`, `done()`, `ok()`, `set(host, text)` and `key(host, key) -> Edited`.
  - `pub enum Edited { Typing, Done, Cancelled, Browse }`.
  - `pub struct Browse { pub dir: PathBuf, pub folders: Vec<String>, pub error: Option<String> }`, with `Browse::at(text)`, `Browse::open(dir)` and `rows()`.
  - `folder::value(theme, &Folder) -> Vec<Span<'static>>`, `folder::help(theme, &Folder) -> Line<'static>` and `folder::bar() -> Bar`.
  - `App::folder_key(key)`, `App::browse_key(key)`, `App::backup_key(key)`, `App::load_backup_choice()` and `App::backup_file(version) -> String`.
  - `Maint::editing() -> bool`.

- [ ] **Step 1: Write the failing tests** (`maint/backup_tests.rs`; add `#[cfg(test)] mod backup_tests;` to `maint/mod.rs`)

```rust
//! Maintenance › Back up and the folder field, key by key.

use std::path::PathBuf;

use crate::tui::{
    app::Key,
    maint::Page,
    nav::Screen,
    script_host::{screen, set_up, type_text},
};

fn folder(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("ov-backup-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("nas")).unwrap();
    dir
}

#[test]
fn back_up_asks_for_a_folder_checks_it_as_typed_and_writes_a_new_file() {
    let dir = folder("now");
    let shown = dir.display().to_string();
    let mut app = set_up(vec![Ok(format!("done\tbackup saved to {shown}/x.dump (431000000 bytes) and {shown}/x.dump.roles.sql\n"))]);
    app.open_page(Page::Backup);
    let text = screen(&app);
    assert!(text.contains("choose a folder") && text.contains("Certificates"), "{text}");
    app.key(Key::Enter);
    assert!(screen(&app).contains("Folder: type, or"), "{}", screen(&app));
    type_text(&mut app, &shown);
    assert!(screen(&app).contains("exists and is writable"), "{}", screen(&app));
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let call = app.host.calls.borrow()[0].0.clone();
    let version = env!("CARGO_PKG_VERSION");
    assert!(call.starts_with(&format!("update-step backup --backup {shown}/openvibes-{version}-")), "{call}");
    assert!(call.ends_with(".dump"), "{call}");
    let text = screen(&app);
    assert!(text.contains("✓ Saved") && text.contains("411 MB"), "{text}");
    assert!(text.contains("Copy it off this host"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Home, "Enter Done goes back to where Back up was opened from");
    assert!(app.run.is_none(), "the result was seen");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn back_up_now_without_a_good_folder_says_so_and_runs_nothing() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Backup);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(app.asking.is_none() && app.host.calls.borrow().is_empty());
    assert!(screen(&app).contains("Choose a folder first"));
    assert_eq!(app.nav.row, 0, "the folder row is highlighted");
}

#[test]
fn esc_while_typing_puts_the_folder_back_and_q_types_into_it() {
    let dir = folder("esc");
    let mut app = set_up(vec![]);
    let memory = app.root.join("etc/openvibes");
    std::fs::create_dir_all(&memory).unwrap();
    std::fs::write(memory.join("backup.toml"), format!("folder = \"{}\"\n", dir.display())).unwrap();
    app.open_page(Page::Backup);
    assert_eq!(app.maint.folder.text, dir.display().to_string(), "the remembered folder");
    app.key(Key::Enter);
    type_text(&mut app, "/q?");
    assert!(app.maint.folder.text.ends_with("/q?") && !app.quit);
    app.key(Key::Esc);
    assert_eq!(app.maint.folder.text, dir.display().to_string());
    assert_eq!(app.nav.screen, Screen::Maint(Page::Backup), "Esc cancels, it does not leave");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn tab_browses_folders_and_use_this_folder_picks_one() {
    let dir = folder("tab");
    let mut app = set_up(vec![]);
    app.open_page(Page::Backup);
    app.key(Key::Enter);
    type_text(&mut app, &dir.display().to_string());
    app.key(Key::Tab);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Folder));
    assert!(screen(&app).contains("nas/"), "{}", screen(&app));
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.maint.browse.as_ref().unwrap().dir, dir.join("nas"));
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Backup));
    assert_eq!(app.maint.folder.text, dir.join("nas").display().to_string());
    assert!(!app.maint.editing(), "picking a folder ends the typing");
    std::fs::remove_dir_all(&dir).unwrap();
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin backup_tests`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `maint/folder.rs`**

```rust
//! The backup folder (approved.md 38): typed in place and checked as
//! typed, or picked with Tab in a browser of folders (⭡⭣, Enter opens,
//! Use this folder picks). Shared by Back up, Update and Uninstall.

use std::path::{Path, PathBuf};

use platform_host::Host;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Page, backup::check_folder};
use crate::tui::{
    app::{App, Key},
    nav::Screen,
    ui::{
        bar::Bar,
        frame,
        list::{self, Row, Scroll},
        logo::Header,
        theme::Theme,
    },
};

#[derive(Debug, Default)]
pub struct Folder {
    pub text: String,
    /// The check of `text`, as typed.
    pub check: Option<Result<String, String>>,
    /// The folder before typing began: Esc puts it back.
    before: Option<String>,
}

pub enum Edited {
    Typing,
    Done,
    Cancelled,
    Browse,
}

impl Folder {
    pub fn editing(&self) -> bool {
        self.before.is_some()
    }
    pub fn edit(&mut self) {
        self.before = Some(self.text.clone());
    }
    pub fn done(&mut self) {
        self.before = None;
    }
    pub fn ok(&self) -> bool {
        matches!(self.check, Some(Ok(_)))
    }
    pub fn set<H: Host>(&mut self, host: &H, text: String) {
        self.check = Some(check_folder(host, &text));
        self.text = text;
    }
    pub fn key<H: Host>(&mut self, host: &H, key: Key) -> Edited {
        let mut text = self.text.clone();
        match key {
            Key::Char(c) if text.chars().count() < 4096 => text.push(c),
            Key::Backspace => {
                text.pop();
            }
            Key::ClearLine => text.clear(),
            Key::Enter => {
                self.done();
                return Edited::Done;
            }
            Key::Esc => {
                if let Some(before) = self.before.take() {
                    self.set(host, before);
                }
                return Edited::Cancelled;
            }
            Key::Tab => return Edited::Browse,
            _ => return Edited::Typing,
        }
        self.set(host, text);
        Edited::Typing
    }
}

/// The folder's value on its row.
pub fn value(theme: &Theme, folder: &Folder) -> Vec<Span<'static>> {
    if folder.editing() {
        vec![Span::raw(format!("{}█", folder.text))]
    } else if folder.ok() {
        vec![Span::raw(folder.text.clone())]
    } else {
        vec![Span::styled("choose a folder", theme.yellow())]
    }
}

/// The help line on the folder's row: the check, or what a folder can be.
pub fn help(theme: &Theme, folder: &Folder) -> Line<'static> {
    match &folder.check {
        Some(Ok(text)) => Line::styled(format!("    {text}."), theme.dim()),
        Some(Err(text)) if folder.editing() || !folder.text.is_empty() => {
            Line::styled(format!("    {text}."), theme.yellow())
        }
        _ => Line::styled("    A NAS mount, a backup disk: any folder this host can write.", theme.dim()),
    }
}

/// The bar while a folder is typed (flows.py).
pub fn bar() -> Bar {
    Bar::edit("Folder", "type, or", &[("Tab", "to browse"), ("Enter", "Done")])
}

pub struct Browse {
    pub dir: PathBuf,
    pub folders: Vec<String>,
    pub error: Option<String>,
}

impl Browse {
    /// At the folder typed so far, else its nearest parent that exists, else /.
    pub fn at(text: &str) -> Browse {
        let mut dir = PathBuf::from(if text.starts_with('/') { text } else { "/" });
        while !dir.is_dir() && dir.pop() {}
        if !dir.is_dir() {
            dir = PathBuf::from("/");
        }
        Browse::open(dir)
    }
    pub fn open(dir: PathBuf) -> Browse {
        match std::fs::read_dir(&dir) {
            Ok(entries) => {
                let mut folders: Vec<String> = entries
                    .filter_map(Result::ok)
                    .filter(|e| e.path().is_dir())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .filter(|name| !name.starts_with('.'))
                    .collect();
                folders.sort();
                Browse { dir, folders, error: None }
            }
            Err(error) => Browse { dir, folders: Vec::new(), error: Some(error.to_string()) },
        }
    }
    fn up(&self) -> Option<&Path> {
        self.dir.parent()
    }
    /// Use this folder, `..` (unless at /), then the folders.
    pub fn rows(&self) -> Vec<(String, String)> {
        let mut rows = vec![("Use this folder".to_owned(), self.dir.display().to_string())];
        if self.up().is_some() {
            rows.push(("..".to_owned(), "up one folder".to_owned()));
        }
        rows.extend(self.folders.iter().map(|f| (format!("{f}/"), String::new())));
        rows
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let Some(browse) = &app.maint.browse else { return };
    let up = usize::from(browse.up().is_some());
    let enter = match app.nav.row {
        0 => "Use this folder",
        1 if up == 1 => "Up one folder",
        _ => "Open",
    };
    let area = frame::draw(frame, t, head, Some("Choose a folder"), &app.bar(Bar::keys(&[("Enter", enter)])));
    let rows: Vec<Row> = browse.rows().iter().map(|(n, v)| Row::entry(n, v)).collect();
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(t, &rows, app.nav.row, &mut scroll, area.height.saturating_sub(1), 22);
    app.nav.scroll.set(scroll);
    lines.push(match &browse.error {
        Some(error) => Line::styled(format!("    {} cannot be read: {error}", browse.dir.display()), t.yellow()),
        None => Line::styled("    Enter opens a folder; Use this folder picks the one shown.", t.dim()),
    });
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Keys while the folder is typed; Tab opens the browser.
    pub(super) fn folder_key(&mut self, key: Key) {
        if let Edited::Browse = self.maint.folder.key(&self.host, key) {
            self.maint.browse = Some(Browse::at(&self.maint.folder.text));
            self.nav.go(Screen::Maint(Page::Folder));
        }
    }

    pub(super) fn browse_key(&mut self, key: Key) {
        let Some(browse) = &self.maint.browse else { return };
        let count = browse.rows().len();
        let dir = browse.dir.clone();
        let up = browse.up().map(Path::to_path_buf);
        let row = self.nav.row;
        let target = match (row, &up) {
            (0, _) => None,
            (1, Some(parent)) => Some(parent.clone()),
            (_, _) => browse.folders.get(row - 1 - usize::from(up.is_some())).map(|f| dir.join(f)),
        };
        if self.move_row(key, count) {
            return;
        }
        match key {
            Key::Esc => {
                self.maint.browse = None;
                self.back();
            }
            Key::Enter if row == 0 => {
                self.maint.browse = None;
                self.maint.folder.set(&self.host, dir.display().to_string());
                self.maint.folder.done();
                self.back();
            }
            Key::Enter => {
                if let Some(next) = target {
                    self.maint.browse = Some(Browse::open(next));
                    self.nav.row = 0;
                    self.nav.scroll.set(Scroll::default());
                }
            }
            _ => {}
        }
    }
}
```

- [ ] **Step 4: Implement the page** (append to `maint/backup.rs`)

```rust
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{failure, folder, human};
use crate::tui::{
    app::{App, Key},
    run::{Call, Kind, Run, Work},
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
    },
};
use platform_host::{StepState, UpdateStep};

/// The size in the helper's "backup saved to X (N bytes) and …".
fn saved(detail: &str) -> Option<String> {
    let n: u64 = detail.split(" (").nth(1)?.split(" bytes)").next()?.parse().ok()?;
    Some(human(n))
}

fn backup_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run.as_ref().filter(|r| matches!(r.work.kind, Kind::Backup { .. }))
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let run = backup_run(app);
    let bar = match run {
        Some(r) if r.running() => Bar::Busy { text: "Backing up the database…".into(), tick: app.tick_count },
        Some(r) if r.ok() => Bar::only(&[("Enter", "Done")]),
        Some(_) => Bar::act(&[("Enter", "Try again")]),
        None if app.maint.folder.editing() => folder::bar(),
        None if app.nav.row == 0 => Bar::keys(&[("Enter", "Choose a folder")]),
        None => Bar::keys(&[("Enter", "Back up now")]),
    };
    let area = frame::draw(frame, t, head, Some("Back up"), &app.bar(bar));
    let mut lines = vec![
        Line::raw(""),
        Line::styled("    The database: findings, alarms, cases, users, settings. Certificates", t.dim()),
        Line::styled("    and keys are not in it: they stay in /etc/openvibes/pki.", t.dim()),
    ];
    let rows = vec![
        Row::Entry { name: vec![Span::raw("Save in folder")], value: folder::value(t, &app.maint.folder) },
        Row::entry("Back up now", "a new file each time"),
    ];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, 5, 14));
    app.nav.scroll.set(scroll);
    match run {
        Some(r) if r.ok() => {
            let Kind::Backup { file } = &r.work.kind else { return };
            let size = r.states[0].as_ref().and_then(|s| saved(s.detail())).unwrap_or_default();
            lines.push(Line::from(vec![
                Span::raw("    "),
                Span::styled("✓", t.green()),
                Span::raw(" Saved "),
                Span::styled(file.clone(), t.bold()),
                Span::raw(format!(" ({size})")),
            ]));
            lines.push(Line::styled(
                "    Copy it off this host: a backup on the same disk does not survive the disk.",
                t.dim(),
            ));
        }
        Some(r) if !r.running() => {
            let why = r.states[0].as_ref().map_or("", StepState::detail);
            lines.extend(failure(t, why, "Nothing was changed: the services keep running."));
        }
        Some(_) => {}
        None if app.nav.row == 0 => lines.push(folder::help(t, &app.maint.folder)),
        None if app.maint.folder.ok() => lines.push(Line::styled(
            format!("    Writes {}.", app.backup_file(env!("CARGO_PKG_VERSION"))),
            t.dim(),
        )),
        None => lines.push(Line::styled("    Choose a folder first.", t.dim())),
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// What the helper remembered, for Back up, Update and Uninstall.
    pub(super) fn load_backup_choice(&mut self) {
        self.maint.memory = Memory::load(&self.root);
        self.maint.first = self.maint.memory.first;
        self.maint.folder = folder::Folder::default();
        if let Some(text) = self.maint.memory.folder.clone() {
            self.maint.folder.set(&self.host, text);
        }
    }

    /// A new file in the chosen folder for data of `version`.
    pub(super) fn backup_file(&self, version: &str) -> String {
        let base = format!(
            "{}/{}",
            self.maint.folder.text.trim().trim_end_matches('/'),
            file_stem(version, chrono::Local::now().naive_local())
        );
        free_path(&base, "dump", |p| Path::new(p).exists() || Path::new(&format!("{p}.roles.sql")).exists())
    }

    pub(super) fn backup_key(&mut self, key: Key) {
        if self.maint.folder.editing() {
            return self.folder_key(key);
        }
        if let Some(run) = backup_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.run = None;
                self.back();
            } else {
                let work = run.work.clone();
                self.begin(work, 0);
            }
            return;
        }
        if self.move_row(key, 2) || key != Key::Enter {
            return;
        }
        if self.nav.row == 0 {
            return self.maint.folder.edit();
        }
        if !self.maint.folder.ok() {
            self.outcome = Some((false, "Choose a folder first".into()));
            self.nav.row = 0;
            return;
        }
        let file = self.backup_file(env!("CARGO_PKG_VERSION"));
        let call = Call::Update(UpdateStep::Backup, vec!["--backup".into(), file.clone()]);
        self.begin(Work::new(Kind::Backup { file }, vec![call]), 0);
    }
}
```

The imports above merge with Task 4's (`Path`, `Host`). Put `use` lines at the top of the file.

`maint/mod.rs`:
- `pub mod folder;`.
- `Page` gets `Backup` (title "Back up"; help "Enter on Save in folder types or browses a folder; Back up now writes a new file there.") and `Folder` (title "Choose a folder"; help "Enter opens a folder; Use this folder picks the one shown.").
- `Maint` gets:

  ```rust
      /// What the helper remembered; read when Back up, Update or Uninstall opens.
      pub memory: backup::Memory,
      /// Back up first (Update, Uninstall): off by default, then the last choice.
      pub first: bool,
      pub folder: folder::Folder,
      pub browse: Option<folder::Browse>,
  ```

  and:

  ```rust
  impl Maint {
      /// A value is being typed on a page: its keys are the page's.
      pub fn editing(&self) -> bool {
          self.folder.editing()
      }
  }
  ```

- `ENTRIES` becomes:

  ```rust
  const ENTRIES: [(Entry, &str); 4] = [
      (Entry::Legacy(Tab::Setup), "Components and ports"),
      (Entry::Page(Page::Database), "Database"),
      (Entry::Page(Page::Backup), "Back up"),
      (Entry::Legacy(Tab::Configuration), "Settings files"),
  ];
  ```

  `value` gets `Entry::Page(Page::Backup) => "save the database to a folder you choose",` and `Entry::Page(Page::Folder) => "",` (`Folder` is never an entry; the arm keeps the match whole).
- In `draw`, add `Page::Backup => backup::draw(frame, head, app),` and `Page::Folder => folder::draw(frame, head, app),`.
- `open_page`: add `Page::Backup => self.load_backup_choice(),` and `Page::Folder => {}`.
- `maint_key` becomes:

  ```rust
      pub(super) fn maint_key(&mut self, page: Page, key: Key) {
          match page {
              Page::Database => {}
              Page::Backup => self.backup_key(key),
              Page::Folder => self.browse_key(key),
          }
      }
  ```

`app.rs`:
- Add `pub root: std::path::PathBuf,`, documented "/ on a host: where the TUI reads `/etc/openvibes/backup.toml` and `/run/openvibes-admin/job`; tests point it elsewhere". Initialise it `std::path::PathBuf::from("/")`.
- In `key()`, after the `asking` routing, add:

  ```rust
          if self.maint.editing() && let Screen::Maint(page) = self.nav.screen.clone() {
              return self.maint_key(page, key);
          }
  ```

`script_host.rs` `app_taken` and `tests.rs` `app`: after `App::new(…)`, add:

```rust
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    app.root = std::env::temp_dir().join(format!("ov-tui-root-{}-{n}", std::process::id()));
```

(`tests.rs`'s `let app` becomes `let mut app`.)

- [ ] **Step 5: Run the tests**

Run: `cargo test -p openvibes-admin`
Expected: PASS.

- [ ] **Step 6: Docs and commit**

Add to the "Administration TUI" section of `docs/components/openvibes-admin.md`:

> **Back up** (Maintenance › Back up): what a backup holds, Save in folder and Back up now. The folder is typed in place and checked as typed: a full path that exists, is a folder and is writable for you, with the space left (`df`). Tab browses folders instead. No folder is shown or assumed until you choose one; the helper remembers it after the first backup written there. Every backup gets a new name, `openvibes-<version>-<date>-<HHMM>.dump` (`-2`, `-3`… within the same minute). It runs `helper update-step backup --backup FILE` on the worker, then shows the file and its size, and says to copy it off this host. *Ceiling:* a root-squashed NFS folder passes the check (you can write there) but the helper, as root, cannot: the backup then fails with that error and nothing else runs.

```bash
git add -A crates/openvibes-admin docs/components/openvibes-admin.md
git commit -m "TUI: Maintenance › Back up, the folder field and the folder browser"
```

---

### Task 6: Maintenance › Update OpenVIBES

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/update.rs` and `crates/openvibes-admin/src/tui/maint/update_tests.rs`.
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs`:
  - `Page::Update` and `Page::WhatsNew`; `pub enum Then { Update }`.
  - `maint_yes`, the menu entry, and `value` gains `app`.
  - `half_done_problem`, and `run_ended` (called by `run.rs`).
- Modify: `crates/openvibes-admin/src/tui/run.rs`: call `self.run_ended()` where a run ends (end of `start` in the no-worker case, and in `poll_runs` when `ended` became `Some` there).
- Modify: `crates/openvibes-admin/src/tui/work.rs`:
  - `Question::Maint { text: String, detail: String, then: Then }`.
  - `question_key` → `maint_yes`.
  - `bar()` renders it.
- Modify: `crates/openvibes-admin/src/tui/app.rs`:
  - Field `packages: Option<Result<Vec<PackageUpdate>, String>>`.
  - `updates` carries `Result<Vec<PackageUpdate>, HostError>`.
  - `newer_admin(&[PackageUpdate])`.
  - Fields `half_done: Option<String>` and `reopen: bool`.
  - `files_changed()`.
- Modify: `crates/openvibes-admin/src/tui/mod.rs`:
  - The update thread sends `packages()` whole.
  - `reopen()` (exec) when `app.reopen`.
- Modify: `crates/openvibes-admin/src/tui/status.rs`:
  - `Fix::Finish(Page)` and `status_items` adds the half-done problem.
  - The Enter label "Finish it".
- Modify: `crates/openvibes-admin/src/tui/work.rs` `ask_fix`: `Fix::Finish(page) => self.open_page(page)`.
- Modify: `crates/openvibes-admin/src/setup/system.rs`:
  - `job_begin` writes the mark 0644.
  - `job_guard`'s message names the Maintenance page.
- Delete today's update path:
  - In `tui/maintain.rs`: `UPDATE_START_ROW`, `open_update`, `update_key`, and the `(Phase::Update, 0)` arm of `maintain_field`.
  - In `tui/maintain_view.rs`: `update_lines`, and the `UPDATE_START_ROW` import.
  - In `tui/setup.rs`: `Phase::Update`, its arm in `setup_key`, `Key::Char('u')` in `setup_status_key`, and `Setup.packages` with its initialiser.
  - In `tui/setup_view.rs`: the `Phase::Update` arm, and `u update` in `RUN_KEYS` and `DONE_KEYS`.
  - In `tui/jobs.rs`: `Job::Update`, its arms, and the `UpdateStep` import.
  - In `tui/setup_tests.rs`: `update_lists_the_packages_then_runs_the_update_job`, and `"u update"` in `a_set_up_host_offers_the_maintenance_actions`.
- Modify: `crates/openvibes-admin/src/tui/nav_tests.rs`: `the_update_notice_arrives_from_the_background_without_blocking` sends `Ok(vec![PackageUpdate { name: "openvibes-admin".into(), installed: "0.2.8-1.fc44".into(), available: Some("0.3.0-1.fc44".into()) }])` instead of `Some("0.3.0".to_owned())`.

**Interfaces:**
- Consumes: `Run`, `Work`, `Rescue` and `App::begin` (Task 2); the folder and backup items (Tasks 4–5); `ui::steps::lines` (Task 1).
- Produces:
  - `pub const STEPS: [&str; 6]`.
  - `pub fn work(to: &str, backup: Option<&str>, finish: bool) -> Work`.
  - `pub fn half_done(root: &Path) -> Option<String>`.
  - `App::update_key`, `App::update_yes`, `App::run_ended` and `App::files_changed`.
  - `Fix::Finish(Page)`.
  - `Question::Maint { … }`.
  - `pub fn newer_admin(packages: &[PackageUpdate]) -> Option<String>`.

- [ ] **Step 1: Write the failing tests** (`maint/update_tests.rs`; add `#[cfg(test)] mod update_tests;` to `maint/mod.rs`)

```rust
//! Maintenance › Update OpenVIBES, key by key (maint1.py, flows.py,
//! backupfolder.py, backupdefault.py, general.py).

use std::path::Path;

use platform_host::HostError;

use crate::tui::{
    app::{App, Key},
    maint::Page,
    nav::Screen,
    script_host::{SetupHost, screen, set_up, type_text},
    status::Item,
};

fn update_app(answers: Vec<Result<String, HostError>>) -> App<SetupHost> {
    let mut app = set_up(answers);
    app.update = Some("0.2.9".into());
    app.packages = Some(Ok(Vec::new()));
    app
}

fn remember(app: &App<SetupHost>, text: &str) {
    let dir = app.root.join("etc/openvibes");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("backup.toml"), text).unwrap();
}

fn temp(name: &str) -> String {
    let dir = std::env::temp_dir().join(format!("ov-update-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir.display().to_string()
}

fn yes_and_password(app: &mut App<SetupHost>) {
    app.key(Key::Enter);
    type_text(app, "pw");
    app.key(Key::Enter);
}

#[test]
fn the_first_update_offers_no_folder_and_back_up_first_is_off() {
    let mut app = update_app(vec![]);
    app.open_page(Page::Update);
    let text = screen(&app);
    for want in [
        &format!("v{} installed", env!("CARGO_PKG_VERSION")),
        "0.2.9 available",
        "[ ] Back up first",
        "no folder chosen yet",
        "Update now",
        "What's new",
        "Off unless you chose it last time.",
        "Space  Select/deselect",
    ] {
        assert!(text.contains(want.as_str()), "missing {want:?} in\n{text}");
    }
}

#[test]
fn ticking_back_up_first_needs_a_folder_before_update_now() {
    let mut app = update_app(vec![]);
    app.open_page(Page::Update);
    app.key(Key::Char(' '));
    let text = screen(&app);
    assert!(text.contains("[x] Back up first") && text.contains("choose a folder"), "{text}");
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(app.question.is_none(), "no question without a folder");
    assert_eq!(app.nav.row, 1, "Save in folder is highlighted");
    assert!(screen(&app).contains("Choose a folder for the backup first"));
}

#[test]
fn update_with_a_remembered_folder_runs_six_steps_with_a_new_file() {
    let dir = temp("six");
    let mut app = update_app(vec![]);
    remember(&app, &format!("folder = \"{dir}\"\nfirst = true\n"));
    app.open_page(Page::Update);
    let text = screen(&app);
    assert!(text.contains("[x] Back up first") && text.contains("Ticked because you backed up last time"), "{text}");
    app.nav.row = 2;
    app.key(Key::Enter);
    assert!(screen(&app).contains("Update to 0.2.9?"));
    yes_and_password(&mut app);
    let calls = app.host.calls.borrow().clone();
    assert_eq!(calls.len(), 6);
    assert!(
        calls[0].0.starts_with(&format!("update-step backup --remember-choice --backup {dir}/openvibes-0.2.9-")),
        "{}",
        calls[0].0
    );
    assert!(calls[5].0.starts_with("update-step ready"));
    let text = screen(&app);
    assert!(text.contains("Updated to 0.2.9 · everything is ready"), "{text}");
    assert!(text.contains("Enter  Open 0.2.9"), "{text}");
    app.key(Key::Enter);
    assert!(app.reopen, "Enter starts the new version");
}

#[test]
fn without_back_up_first_the_choice_is_still_remembered() {
    let mut app = update_app(vec![]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    yes_and_password(&mut app);
    assert_eq!(app.host.calls.borrow()[0].0, "update-step backup --remember-choice");
}

#[test]
fn a_failed_upgrade_starts_the_services_again_and_says_so() {
    let mut app = update_app(vec![
        Ok("skipped\tno backup chosen\n".into()),
        Ok("done\tstopped\n".into()),
        Ok("failed\trepo.openvibes.org timed out after 30 s\n".into()),
        Ok("done\tstarted again\n".into()),
    ]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    yes_and_password(&mut app);
    assert!(app.host.calls.borrow()[3].0.starts_with("update-step start"));
    let text = screen(&app);
    for want in ["✗ Install packages", "timed out", "started again as they were", "Try again"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert!(app.host.calls.borrow()[4].0.starts_with("update-step stop"), "Try again stops them again first");
}

#[test]
fn a_failed_migration_keeps_the_services_stopped_and_says_why() {
    let mut app = update_app(vec![
        Ok("skipped\tno backup chosen\n".into()),
        Ok("done\tstopped\n".into()),
        Ok("done\tupgraded\n".into()),
        Ok("failed\tschema 47 needs a backup first\n".into()),
    ]);
    app.open_page(Page::Update);
    app.nav.row = 1;
    app.key(Key::Enter);
    yes_and_password(&mut app);
    assert_eq!(app.host.calls.borrow().len(), 4, "the old services are not started on a new schema");
    assert!(screen(&app).contains("the database is not yet"));
}

#[test]
fn a_half_done_update_is_a_status_problem_and_finishes_without_a_new_version() {
    let mut app = set_up(vec![]);
    app.packages = Some(Ok(Vec::new()));
    let run = app.root.join("run/openvibes-admin");
    std::fs::create_dir_all(&run).unwrap();
    std::fs::write(run.join("job"), "update").unwrap();
    app.files_changed();
    assert!(matches!(&app.status_items()[0], Item::Problem { text, .. } if text.contains("update stopped half way")));
    app.open_page(Page::Update);
    assert!(screen(&app).contains("Finish the update"));
    app.key(Key::Enter);
    assert!(screen(&app).contains("Finish the update?"));
    yes_and_password(&mut app);
    assert!(app.host.calls.borrow()[0].0.starts_with("update-step stop"), "no backup when finishing");
    assert_eq!(app.host.calls.borrow().len(), 5);
}

#[test]
fn whats_new_lists_every_package_and_up_to_date_offers_only_it() {
    let mut app = set_up(vec![]);
    app.packages = Some(Ok(vec![platform_host::PackageUpdate {
        name: "openvibes-ingest".into(),
        installed: "0.2.8-1.fc44".into(),
        available: None,
    }]));
    app.open_page(Page::Update);
    let text = screen(&app);
    assert!(text.contains("up to date") && !text.contains("Update now"), "{text}");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::WhatsNew));
    let text = screen(&app);
    assert!(text.contains("openvibes-ingest") && text.contains("0.2.8-1.fc44 · up to date"), "{text}");
    assert!(text.contains("releases/tag/v"), "{text}");
}

#[test]
fn the_half_done_mark_is_read_from_run() {
    let root = std::env::temp_dir().join(format!("ov-half-{}", std::process::id()));
    std::fs::create_dir_all(root.join("run/openvibes-admin")).unwrap();
    assert_eq!(super::update::half_done(&root), None);
    std::fs::write(root.join("run/openvibes-admin/job"), "uninstall\n").unwrap();
    assert_eq!(super::update::half_done(&root).as_deref(), Some("uninstall"));
    assert_eq!(super::update::half_done(Path::new("/nonexistent")), None);
    std::fs::remove_dir_all(&root).unwrap();
}
```

In `setup/system.rs` tests (or `update.rs`'s `a_half_done_update_blocks_other_setup_runs`), add after its existing assert:

```rust
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(fake.root.join("run/openvibes-admin/job")).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644, "the TUI reads the mark as the operator");
        assert!(refused.contains("Maintenance › Update OpenVIBES"), "{refused}");
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin update_tests a_half_done_update_blocks`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `maint/update.rs`**

```rust
//! Maintenance › Update OpenVIBES (spec §6; maint1.py, flows.py): what is
//! installed and what is new; Back up first (off by default, then your
//! last choice) with its folder; Update now with the standard question;
//! six steps; one result line. A failure while stopping or installing
//! starts the services again; a half-done update can be finished.

use std::path::Path;

use platform_host::{Host, StepState, UpdateStep};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Page, Then, failure, folder};
use crate::tui::{
    app::{App, Key, Question},
    nav::Screen,
    run::{Call, Kind, Rescue, Run, Work},
    ui::{
        bar::Bar,
        frame,
        list::{self, Row},
        logo::Header,
        steps,
    },
};

pub const STEPS: [&str; 6] =
    ["Back up", "Stop services", "Install packages", "Update the database", "Start services", "Ready"];
const RELEASES: &str = "https://github.com/openvibes-project/openvibes-platform/releases/tag/";

/// The kind of a job left half done (`update`, `uninstall`): the helper's
/// mark in /run, readable by all.
pub fn half_done(root: &Path) -> Option<String> {
    let text = std::fs::read_to_string(root.join("run/openvibes-admin/job")).ok()?;
    let kind = text.trim();
    (!kind.is_empty()).then(|| kind.to_owned())
}

/// The update's calls (from Stop when finishing a half-done one); a stop
/// while stopping or installing starts the services again.
pub fn work(to: &str, backup: Option<&str>, finish: bool) -> Work {
    let mut args = vec!["--remember-choice".to_owned()];
    if let Some(file) = backup {
        args.extend(["--backup".to_owned(), file.to_owned()]);
    }
    let skip = usize::from(finish);
    let calls = UpdateStep::ALL[skip..].iter().map(|s| Call::Update(*s, args.clone())).collect();
    Work {
        kind: Kind::Update { to: to.to_owned() },
        calls,
        rescue: Some(Rescue { from: 1 - skip, to: 3 - skip, calls: vec![Call::Update(UpdateStep::Start, args)] }),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Choice {
    First,
    Folder,
    Update,
    WhatsNew,
}

/// What Update now installs, and whether it finishes a half-done update.
fn target<H: Host>(app: &App<H>) -> Option<(String, bool)> {
    if app.half_done.as_deref() == Some("update") {
        let to = app.update.clone().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
        return Some((to, true));
    }
    app.update.clone().map(|to| (to, false))
}

fn choices<H: Host>(app: &App<H>) -> Vec<Choice> {
    let mut out = Vec::new();
    match target(app) {
        Some((_, false)) => {
            out.push(Choice::First);
            if app.maint.first {
                out.push(Choice::Folder);
            }
            out.push(Choice::Update);
        }
        Some((_, true)) => out.push(Choice::Update),
        None => {}
    }
    out.push(Choice::WhatsNew);
    out
}

fn update_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run.as_ref().filter(|r| matches!(r.work.kind, Kind::Update { .. }))
}

fn row<H: Host>(app: &App<H>, choice: Choice) -> Row {
    let t = &app.theme;
    match choice {
        Choice::First => {
            let mark = if app.maint.first { Span::styled("[x]", t.green()) } else { Span::raw("[ ]") };
            let value = match (&app.maint.memory.folder, app.maint.first) {
                (_, true) => String::new(),
                (Some(folder), false) => folder.clone(),
                (None, false) => "no folder chosen yet".into(),
            };
            Row::Entry { name: vec![mark, Span::raw(" Back up first")], value: vec![Span::styled(value, t.dim())] }
        }
        Choice::Folder => Row::Entry { name: vec![Span::raw("Save in folder")], value: folder::value(t, &app.maint.folder) },
        Choice::Update if target(app).is_some_and(|(_, finish)| finish) => {
            Row::entry("Finish the update", "the services are stopped until it ends")
        }
        Choice::Update => Row::entry("Update now", "services stop while it runs"),
        Choice::WhatsNew => Row::entry("What's new", "the release notes"),
    }
}

fn help<H: Host>(app: &App<H>, choice: Choice) -> Line<'static> {
    let t = &app.theme;
    let dim = |text: String| Line::styled(format!("    {text}"), t.dim());
    match choice {
        Choice::First if app.maint.memory.first => {
            dim("Ticked because you backed up last time · a new file each time.".into())
        }
        Choice::First => dim("Off unless you chose it last time.".into()),
        Choice::Folder => folder::help(t, &app.maint.folder),
        Choice::Update if app.maint.first && app.maint.folder.ok() => {
            let to = target(app).map(|(to, _)| to).unwrap_or_default();
            dim(format!("Backs up to {} first.", app.backup_file(&to)))
        }
        Choice::Update => dim("Stops the services, installs the packages, updates the database, starts again.".into()),
        Choice::WhatsNew => dim("Every package's version, and where the release notes are.".into()),
    }
}

fn info<H: Host>(app: &App<H>) -> Vec<Line<'static>> {
    let t = &app.theme;
    let installed = Span::raw(format!("    v{} installed · ", env!("CARGO_PKG_VERSION")));
    let first = match (&app.packages, &app.update) {
        (_, Some(to)) => Line::from(vec![installed, Span::styled(format!("{to} available"), t.yellow())]),
        (None, None) => Line::from(vec![installed, Span::styled("looking for updates…", t.dim())]),
        (Some(Err(error)), None) => {
            Line::from(vec![installed, Span::styled(format!("could not look for updates: {error}"), t.yellow())])
        }
        (Some(Ok(_)), None) => Line::from(vec![installed, Span::raw("up to date")]),
    };
    let second = if target(app).is_some_and(|(_, finish)| finish) {
        Line::from(vec![
            Span::raw("    "),
            Span::styled("An update stopped half way:", t.yellow()),
            Span::raw(" the services may be stopped until it ends."),
        ])
    } else {
        Line::styled("    Updates every OpenVIBES package on this host, then the database.", t.dim())
    };
    vec![first, second]
}

/// What to do after a stop, by the step it stopped at (counted in STEPS).
fn after(run: &Run, skip: usize) -> String {
    let at = run.stopped_at().unwrap_or(0) + skip;
    match (at, run.rescued(0)) {
        (0, _) => "The services keep running; nothing was changed.".into(),
        (1 | 2, Some(s)) if s.finished() => {
            "The services are started again as they were; nothing was changed.".into()
        }
        (1 | 2, Some(s)) => format!("The services could not be started again ({}): see Status.", s.detail()),
        (1 | 2, None) => "The services are being started again…".into(),
        (3, _) => "The packages are new but the database is not yet: Try again finishes it. \
                   The services stay stopped until then."
            .into(),
        (4, _) => "Some services did not start: see Status, then Try again.".into(),
        _ => "Everything is updated, but a service is not ready yet: see Status.".into(),
    }
}

/// Where Try again starts: from Stop when the rescue started the services again.
fn retry_from(run: &Run, skip: usize) -> usize {
    match run.stopped_at().map(|at| at + skip) {
        None | Some(0) => 0,
        Some(1 | 2) => 1 - skip,
        Some(at) => at - skip,
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = update_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let choices = choices(app);
    let chosen = choices.get(app.nav.row).copied();
    let bar = match chosen {
        Some(Choice::First) => Bar::keys(&[("Space", "Select/deselect"), ("Enter", "Confirm")]),
        Some(Choice::Folder) if app.maint.folder.editing() => folder::bar(),
        Some(Choice::Folder) => Bar::keys(&[("Enter", "Choose a folder")]),
        Some(Choice::Update) if target(app).is_some_and(|(_, f)| f) => Bar::keys(&[("Enter", "Finish the update")]),
        Some(Choice::Update) => Bar::keys(&[("Enter", "Update now")]),
        Some(Choice::WhatsNew) | None => Bar::keys(&[("Enter", "What's new")]),
    };
    let area = frame::draw(frame, t, head, Some("Update OpenVIBES"), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(info(app));
    let rows: Vec<Row> = choices.iter().map(|c| row(app, *c)).collect();
    let room = area.height.saturating_sub(u16::try_from(lines.len() + 1).unwrap_or(u16::MAX));
    let height = u16::try_from(rows.len() * 2 + 1).unwrap_or(u16::MAX).min(room);
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, height, 24));
    app.nav.scroll.set(scroll);
    if let Some(choice) = chosen {
        lines.push(help(app, choice));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let Kind::Update { to } = &run.work.kind else { return };
    let skip = UpdateStep::ALL.len() - run.work.calls.len();
    let titles: Vec<String> = STEPS[skip..].iter().map(|s| (*s).to_owned()).collect();
    let open = format!("Open {to}");
    let bar = match run.current() {
        Some(i) => Bar::Busy { text: format!("Step {} of {}: {}", i + 1, titles.len(), titles[i]), tick: app.tick_count },
        None if run.running() => Bar::Busy { text: "Starting the services again…".into(), tick: app.tick_count },
        None if run.ok() => Bar::only(&[("Enter", open.as_str())]),
        None => Bar::act(&[("Enter", "Try again")]),
    };
    let area = frame::draw(frame, t, head, Some(&format!("Updating to {to}")), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(steps::lines(t, &titles, &run.states, run.current(), app.tick_count, 6));
    lines.push(Line::raw(""));
    if run.ok() {
        lines.push(Line::styled(format!("    ✓ Updated to {to} · everything is ready ({})", run.took()), t.green()));
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        lines.extend(failure(t, why, &after(run, skip)));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw_whats_new<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let area = frame::draw(frame, t, head, Some("What's new"), &app.bar(Bar::act(&[])));
    let mut lines = vec![Line::raw("")];
    match &app.packages {
        Some(Ok(packages)) => lines.extend(packages.iter().map(|p| {
            let change = p
                .available
                .as_ref()
                .map_or_else(|| format!("{} · up to date", p.installed), |a| format!("{} → {a}", p.installed));
            Line::raw(format!("    {:<26} {change}", p.name))
        })),
        Some(Err(error)) => lines.push(Line::styled(format!("    could not look for updates: {error}"), t.yellow())),
        None => lines.push(Line::styled("    looking for updates…", t.dim())),
    }
    let version = app.update.clone().unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_owned());
    lines.push(Line::raw(""));
    lines.push(Line::styled(format!("    Release notes: {RELEASES}v{version}"), t.dim()));
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn update_key(&mut self, key: Key) {
        if self.maint.folder.editing() {
            return self.folder_key(key);
        }
        if let Some(run) = update_run(self) {
            if run.running() || key != Key::Enter {
                return;
            }
            if run.ok() {
                self.reopen = true;
            } else {
                let skip = UpdateStep::ALL.len() - run.work.calls.len();
                let (work, from) = (run.work.clone(), retry_from(run, skip));
                self.begin(work, from);
            }
            return;
        }
        let choices = choices(self);
        if self.move_row(key, choices.len()) {
            return;
        }
        match (choices.get(self.nav.row), key) {
            (Some(Choice::First), Key::Char(' ')) => self.maint.first = !self.maint.first,
            (Some(Choice::Folder), Key::Enter) => self.maint.folder.edit(),
            (Some(Choice::WhatsNew), Key::Enter) => self.nav.go(Screen::Maint(Page::WhatsNew)),
            (Some(Choice::First | Choice::Update), Key::Enter) => self.ask_update(),
            _ => {}
        }
    }

    fn ask_update(&mut self) {
        let Some((to, finish)) = target(self) else { return };
        if self.maint.first && !finish && !self.maint.folder.ok() {
            self.outcome = Some((false, "Choose a folder for the backup first".into()));
            self.nav.row = 1;
            return;
        }
        let (text, detail) = if finish {
            ("Finish the update?".to_owned(), "the services start again")
        } else {
            (format!("Update to {to}?"), "services stop while it runs")
        };
        self.question = Some((Question::Maint { text, detail: detail.into(), then: Then::Update }, true));
    }

    pub(super) fn update_yes(&mut self) {
        let Some((to, finish)) = target(self) else { return };
        let file = (self.maint.first && !finish).then(|| self.backup_file(&to));
        self.begin(work(&to, file.as_deref(), finish), 0);
    }
}
```

`maint/mod.rs`:
- Add `mod update;`.
- `Page` gets `Update` (title "Update OpenVIBES"; help "Space ticks Back up first; Enter on Update now updates; What's new lists the packages.") and `WhatsNew` (title "What's new"; help "A list: every package's version and the release notes' address.").
- Add:

  ```rust
  /// What Yes to a Maintenance question does.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub enum Then {
      Update,
  }
  ```

- `ENTRIES` becomes `[(Entry, &str); 5]`, with `(Entry::Page(Page::Update), "Update OpenVIBES")` first.
- `value` becomes `fn value<H: Host>(app: &App<H>, entry: Entry) -> String`:
  - Its arms return `.into()`.
  - `Entry::Page(Page::Update)` is `match &app.update { Some(v) => format!("{v} is available"), None => "up to date".into() }`.
  - `Page::WhatsNew` returns `String::new()`.
  - `draw_menu` calls `value(app, *e)`.
- In `draw`, add `Page::Update => update::draw(…)` and `Page::WhatsNew => update::draw_whats_new(…)`.
- `open_page`: add `Page::Update => self.load_backup_choice(),` and `Page::WhatsNew => {}`.
- `maint_key`: add `Page::Update => self.update_key(key),` and `Page::WhatsNew => {}`.
- Add:

  ```rust
  impl<H: Host> App<H> {
      pub(super) fn maint_yes(&mut self, then: Then) {
          match then {
              Then::Update => self.update_yes(),
          }
      }

      /// A run ended: the files it changes are read again.
      pub(super) fn run_ended(&mut self) {
          self.files_changed();
      }
  }

  /// Status's problem for a half-done job (decision 17).
  pub fn half_done_problem(kind: Option<&str>) -> Option<super::status::Item> {
      let (text, page) = match kind? {
          "update" => ("An update stopped half way: the services may be stopped", Page::Update),
          _ => return None,
      };
      Some(super::status::Item::Problem { text: text.into(), fix: Some(super::status::Fix::Finish(page)) })
  }
  ```

`app.rs`:
- Add the fields `pub packages: Option<Result<Vec<PackageUpdate>, String>>,`, `pub half_done: Option<String>,` and `pub reopen: bool,`, initialised `None`, `None` and `false`. After building `app` in `lazy`, call `app.files_changed();`.
- Change `updates` to `Option<Receiver<Result<Vec<PackageUpdate>, HostError>>>`.
- Add:

  ```rust
      /// Reads again what the helper writes for the TUI (the half-done mark).
      pub(super) fn files_changed(&mut self) {
          self.half_done = super::maint::update_half_done(&self.root);
      }
  ```

  (Re-export it in `maint/mod.rs`: `pub use update::half_done as update_half_done;`.)
- In `tick()`, the versions block becomes:

  ```rust
          if !self.versions_loaded {
              let found = match self.updates.as_ref().map(Receiver::try_recv) {
                  Some(Err(TryRecvError::Empty)) => None,
                  Some(Ok(found)) => Some(found),
                  Some(Err(TryRecvError::Disconnected)) => {
                      Some(Err(HostError::Failed("the update check stopped".into())))
                  }
                  None => Some(self.host.packages()),
              };
              if let Some(found) = found {
                  self.update = found.as_ref().ok().and_then(|p| newer_admin(p));
                  self.packages = Some(found.map_err(|e| e.to_string()));
                  self.versions_loaded = true;
                  self.updates = None;
              }
          }
  ```

- `newer_admin` becomes:

  ```rust
  pub fn newer_admin(packages: &[PackageUpdate]) -> Option<String> {
      packages.iter().find_map(|p| {
          let v = p.available.as_ref().filter(|_| p.name == "openvibes-admin")?;
          Some(v.split('-').next().unwrap_or(v).to_owned())
      })
  }
  ```

`mod.rs`:
- The update thread becomes `let _ = send.send(Native { runner: SystemRunner }.packages());`.
- Make the terminal mutable (`let mut terminal = ratatui::init();`), and at the end of the loop body add:

  ```rust
          if app.reopen {
              ratatui::restore();
              let error = reopen();
              // Only reached when exec failed.
              terminal = ratatui::init();
              app.reopen = false;
              app.outcome = Some((false, format!("could not start the new version: {error}")));
          }
  ```

- And:

  ```rust
  /// Replaces this process with the updated menu (`exec`); returns only on failure.
  // One of the places the platform starts a process (clippy.toml): a fixed
  // path, no arguments, no shell; the environment (and sudo's) is kept.
  #[allow(clippy::disallowed_types)]
  fn reopen() -> std::io::Error {
      use std::os::unix::process::CommandExt;
      std::process::Command::new("/usr/bin/openvibes-admin").exec()
  }
  ```

`run.rs`:
- In `start`, the last lines become:

  ```rust
          let ended = !run.running();
          *slot = Some(run);
          if again {
              self.ask_again(background);
          }
          if ended {
              self.run_ended();
          }
  ```

- In `poll_runs`, the body of the `for background` loop becomes:

  ```rust
              let slot = if background { &mut self.load } else { &mut self.run };
              let Some(run) = slot.as_mut() else { continue };
              let was = run.running();
              let mut again = false;
              loop { /* unchanged */ }
              let ended = was && !run.running();
              if again {
                  self.ask_again(background);
              }
              if ended {
                  self.run_ended();
              }
  ```

`work.rs`:
- `Question` gets:

  ```rust
      /// A Maintenance question; Yes does `then`.
      Maint { text: String, detail: String, then: super::maint::Then },
  ```

- `question_key`: add `Question::Maint { then, .. } => self.maint_yes(then),`.
- `bar()`: add `Question::Maint { text, detail, .. } => (text.clone(), detail.clone()),`.
- `ask_fix`: add `Fix::Finish(page) => self.open_page(page),`.

`status.rs`:
- `Fix` gets `Finish(super::maint::Page),`.
- `status_items` becomes:

  ```rust
      pub(super) fn status_items(&self) -> Vec<Item> {
          let mut out = items(&self.services, &self.database.health);
          if let Some(problem) = super::maint::half_done_problem(self.half_done.as_deref()) {
              out.insert(0, problem);
          }
          out
      }
  ```

- In `draw`'s `enter` match, add `Some(Item::Problem { fix: Some(Fix::Finish(_)), .. }) => Some("Finish it".to_owned()),`.

`setup/system.rs`:
- `job_begin`'s mode becomes `0o644`, with the doc line "World-readable: the TUI shows a half-done job on Status."
- `job_guard`'s message becomes:

  ```rust
              let page = if other == "update" { "Update OpenVIBES" } else { "Uninstall" };
              Err(format!(
                  "an {other} is half done on this host: finish it first (Maintenance › {page}, or setup --{other})"
              ))
  ```

Then delete today's update path, as listed under **Files**.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin`
Expected: PASS.

- [ ] **Step 5: Docs and commit**

In `docs/components/openvibes-admin.md`:
- From the Maintenance › Setup paragraph, remove the `` `u` update (…) `` clause.
- Add:

  > **Update OpenVIBES** (Maintenance): the installed version and whether a newer one is available (from the package check made at start), then Back up first, Update now and What's new. Back up first is off on a first update; afterwards it is ticked or not as you chose last time, and the help line says why. Ticked, it shows Save in folder (as in Back up; no folder until you choose one). Update now asks "Update to X?" and runs the six update steps on the worker (Back up, Stop services, Install packages, Update the database, Start services, Ready), each shown with ✓, the spinner or ·. A stop at Stop services or Install packages starts the services again (`update-step start`) and says so. A stop at the database step keeps them stopped and says why; Try again goes on. Enter after a successful update starts the new version of the menu. What's new lists every package's version change and the release notes' address. A half-done update (the helper's mark `/run/openvibes-admin/job`, now 0644) is a problem on Status ("Enter Finish it"), and the page then offers Finish the update without a backup, even when nothing newer exists.

```bash
git add -A crates/openvibes-admin docs/components/openvibes-admin.md
git commit -m "TUI: Maintenance › Update OpenVIBES; a failed update starts the services again"
```

---

### Task 7: Maintenance › Repair

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/repair.rs` and `crates/openvibes-admin/src/tui/maint/repair_tests.rs`.
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs`:
  - `Page::Repair`, the entry "Repair" (second), and the routing.
  - `run_ended` sets the Fix result in the bar.
- Delete today's check and repair:
  - In `tui/setup.rs`: `Key::Char('c')` and `Key::Char('r')` in `setup_status_key`; `After::Status` with its arms in `password_key`, `wrong_password` and `with_password`.
  - In `tui/setup_view.rs`: `c check  r repair` in `DONE_KEYS`, and `c check` in `RUN_KEYS`. `r retry` stays: it retries a stopped install.
  - In `tui/setup_tests.rs`: `repair_runs_every_step_in_repair_mode`; and in `a_set_up_host_offers_the_maintenance_actions`, the list becomes `["m components", "p ports"]`.
- Modify: `crates/openvibes-admin/src/tui/nav_tests.rs`: `q_types_into_a_set_up_hosts_setup_password_and_quits_nothing_there` is replaced by the test below.

**Interfaces:**
- Consumes: `Call::Status`, `Call::Repair`, `Kind::Check` and `Kind::Fix` (Task 2); `ui::steps` (Task 1).
- Produces:
  - `pub fn parse(out: &str) -> Vec<(Step, StepState)>`.
  - `pub fn check_work() -> Work` and `pub fn fix_work() -> Work`.
  - `App::repair_key`.

- [ ] **Step 1: Write the failing tests** (`maint/repair_tests.rs`)

```rust
//! Maintenance › Repair, key by key (maint1.py).

use platform_host::{Step, StepState};

use crate::tui::{
    app::Key,
    maint::{Page, repair::parse},
    script_host::{screen, set_up, type_text},
};

const TWO_PROBLEMS: &str = "packages\tdone\tall installed\n\
    certificates\ttodo\t\n\
    firewall\tfailed\t18424/tcp is closed\n\
    services\tdone\t8 of 8 running\n";

fn all_fine() -> String {
    Step::ALL.iter().map(|s| format!("{}\tdone\tok\n", s.name())).collect()
}

#[test]
fn the_status_output_is_read_step_by_step() {
    let steps = parse(TWO_PROBLEMS);
    assert_eq!(steps.len(), 4);
    assert_eq!(steps[2], (Step::Firewall, StepState::Failed("18424/tcp is closed".into())));
}

#[test]
fn repair_checks_first_then_lists_the_problems_and_fixes_them() {
    let mut answers = vec![Ok(TWO_PROBLEMS.to_owned())];
    answers.extend(Step::ALL.iter().map(|_| Ok("done\tok\n".to_owned())));
    answers.push(Ok(all_fine()));
    let mut app = set_up(answers);
    app.open_page(Page::Repair);
    assert!(screen(&app).contains("Your password (sudo):"), "it checks first: the password");
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow()[0].0, "setup-status");
    let text = screen(&app);
    for want in ["2 problems found", "Firewall", "18424/tcp is closed", "other steps in order", "Fix 2 problems", "Check again"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = app.host.calls.borrow().clone();
    assert_eq!(calls[1].0, "setup-step packages --repair");
    assert_eq!(calls.last().unwrap().0, "setup-status", "it checks again after fixing");
    let text = screen(&app);
    assert!(text.contains("Everything is in order") && text.contains("Repaired"), "{text}");
    assert!(!text.contains("Fix 2"), "{text}");
}

#[test]
fn a_fix_that_stops_says_where_and_tries_again_from_there() {
    let mut answers = vec![Ok(TWO_PROBLEMS.to_owned())];
    answers.push(Ok("done\tok\n".into()));
    answers.push(Ok("failed\tpostgresql did not start\n".into()));
    let mut app = set_up(answers);
    app.open_page(Page::Repair);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(text.contains("✗ PostgreSQL") && text.contains("postgresql did not start"), "{text}");
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow()[3].0, "setup-step postgres --repair");
}
```

In `nav_tests.rs`, replacing the removed test:

```rust
#[test]
fn q_types_into_the_password_in_the_bar_and_quits_nothing() {
    let mut app = set_up(vec![]);
    app.open_page(super::maint::Page::Repair);
    type_text(&mut app, "aqb");
    assert_eq!(app.asking.as_ref().unwrap().prompt.typed(), "aqb");
    assert!(!app.quit);
}
```

(`nav_tests.rs` already imports `type_text` for the FakeHost app; this one needs `super::script_host::type_text`. Import it under an alias if the names clash.)

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin repair_tests q_types_into_the_password`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `maint/repair.rs`**

```rust
//! Maintenance › Repair (spec §6; maint1.py): it checks every step first
//! and lists what it found (a report; nothing changes); Fix N problems
//! runs every step in repair mode (never a new CA), then checks again;
//! Check again re-reads.

use std::time::Instant;

use platform_host::{Host, Step, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::failure;
use crate::tui::{
    app::{App, Key},
    run::{Call, Kind, Run, Work},
    ui::{
        bar::{Bar, SPINNER},
        frame,
        list::{self, Row},
        logo::Header,
        steps,
    },
};

/// `setup-status`: `STEP<TAB>STATE<TAB>DETAIL` per line.
pub fn parse(out: &str) -> Vec<(Step, StepState)> {
    out.lines()
        .filter_map(|line| {
            let (name, rest) = line.split_once('\t')?;
            Some((Step::parse(name)?, StepState::parse(rest)?))
        })
        .collect()
}

fn problem(state: &StepState) -> bool {
    matches!(state, StepState::Todo | StepState::Failed(_) | StepState::Waiting(_))
}

pub fn check_work() -> Work {
    Work::new(Kind::Check, vec![Call::Status])
}

pub fn fix_work() -> Work {
    Work::new(Kind::Fix, Step::ALL.iter().map(|s| Call::Repair(*s)).chain([Call::Status]).collect())
}

enum Mode<'a> {
    Waiting,
    Checking,
    Fixing(&'a Run),
    /// The fix stopped at this step.
    Stopped(&'a Run, usize),
    Report(Vec<(Step, StepState)>, Instant),
    /// The check itself failed (wrong password, helper error).
    Failed(String),
}

/// The newest of the last check and the last fix decides what shows.
fn mode<H: Host>(app: &App<H>) -> Mode<'_> {
    let fix = app.run.as_ref().filter(|r| r.work.kind == Kind::Fix);
    let check = app.load.as_ref().filter(|r| r.work.kind == Kind::Check);
    if let Some(run) = fix.filter(|r| r.running()) {
        return Mode::Fixing(run);
    }
    if check.is_some_and(Run::running) {
        return Mode::Checking;
    }
    let newest = match (check, fix) {
        (Some(c), Some(f)) => Some(if c.ended >= f.ended { c } else { f }),
        (c, f) => c.or(f),
    };
    let Some(run) = newest else { return Mode::Waiting };
    let last = run.work.calls.len() - 1;
    match (run.stopped_at(), &run.states[last]) {
        (Some(at), _) if at < last => Mode::Stopped(run, at),
        (_, Some(StepState::Done(out))) => Mode::Report(parse(out), run.ended.unwrap_or(run.started)),
        (_, Some(other)) => Mode::Failed(other.detail().to_owned()),
        (_, None) => Mode::Waiting,
    }
}

fn ago(at: Instant) -> String {
    match at.elapsed().as_secs() / 60 {
        0 => "checked just now".into(),
        1 => "checked a minute ago".into(),
        n => format!("checked {n} minutes ago"),
    }
}

fn entries(steps: &[(Step, StepState)]) -> Vec<(String, String)> {
    let problems: Vec<&str> = steps.iter().filter(|(_, s)| problem(s)).map(|(s, _)| s.title()).collect();
    let mut out = Vec::new();
    if !problems.is_empty() {
        let n = problems.len();
        let name = if n == 1 { "Fix 1 problem".to_owned() } else { format!("Fix {n} problems") };
        out.push((name, problems.join(", ").to_lowercase()));
    }
    out.push(("Check again".to_owned(), String::new()));
    out
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let spin = || Span::styled(SPINNER[app.tick_count % SPINNER.len()], t.teal());
    let mode = mode(app);
    let (title, bar) = match &mode {
        Mode::Fixing(run) => {
            let i = run.current().unwrap_or(0).min(Step::ALL.len() - 1);
            ("Repairing", Bar::Busy { text: format!("Step {} of {}: {}", i + 1, Step::ALL.len(), Step::ALL[i].title()), tick: app.tick_count })
        }
        Mode::Checking => ("Repair", Bar::Busy { text: "Checking every step…".into(), tick: app.tick_count }),
        Mode::Stopped(..) | Mode::Failed(_) => ("Repair", Bar::act(&[("Enter", "Try again")])),
        Mode::Report(steps, _) => {
            let label = entries(steps).get(app.nav.row).map(|(n, _)| n.clone()).unwrap_or_default();
            ("Repair", Bar::keys(&[("Enter", label.as_str())]))
        }
        Mode::Waiting => ("Repair", Bar::act(&[])),
    };
    let area = frame::draw(frame, t, head, Some(title), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    match mode {
        Mode::Waiting => lines.push(Line::styled("    Checking every step needs your password.", t.dim())),
        Mode::Checking => lines.push(Line::from(vec![Span::raw("    "), spin(), Span::raw(" Checking every step…")])),
        Mode::Fixing(run) => {
            let titles: Vec<String> = Step::ALL.iter().map(|s| s.title().to_owned()).collect();
            lines.extend(steps::lines(t, &titles, &run.states, run.current(), app.tick_count, 10));
        }
        Mode::Stopped(run, at) => {
            let titles: Vec<String> = Step::ALL.iter().map(|s| s.title().to_owned()).collect();
            lines.extend(steps::lines(t, &titles, &run.states, None, app.tick_count, 7));
            lines.push(Line::raw(""));
            let why = run.states[at].as_ref().map_or("", StepState::detail);
            lines.extend(failure(t, why, "The steps before it are in order; Try again goes on from here."));
        }
        Mode::Failed(why) => lines.extend(failure(t, &why, "Nothing was changed.")),
        Mode::Report(steps, at) => {
            let problems: Vec<&(Step, StepState)> = steps.iter().filter(|(_, s)| problem(s)).collect();
            lines.push(if problems.is_empty() {
                Line::from(vec![Span::raw("    "), Span::styled("● Everything is in order", t.green()), Span::styled(format!(" · {}", ago(at)), t.dim())])
            } else {
                let n = problems.len();
                let found = if n == 1 { "1 problem found".to_owned() } else { format!("{n} problems found") };
                Line::from(vec![Span::raw("    "), Span::styled(found, t.yellow()), Span::styled(format!(" · {}", ago(at)), t.dim())])
            });
            lines.push(Line::raw(""));
            for (step, state) in &problems {
                let detail = if state.detail().is_empty() { state.label() } else { state.detail() };
                lines.push(Line::from(vec![
                    Span::raw("    "),
                    Span::styled("▲ ", t.yellow()),
                    Span::raw(format!("{:<20} ", step.title())),
                    Span::styled(detail.to_owned(), t.dim()),
                ]));
            }
            let fine = steps.len() - problems.len();
            lines.push(Line::from(vec![Span::raw("    "), Span::styled("✓ ", t.green()), Span::raw(format!("{fine} other steps in order"))]));
            let rows: Vec<Row> = entries(&steps).iter().map(|(n, v)| Row::entry(n, v)).collect();
            let mut scroll = app.nav.scroll.get();
            let height = u16::try_from(rows.len() * 2 + 1).unwrap_or(5);
            lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, height, 22));
            app.nav.scroll.set(scroll);
        }
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Opens Repair: it checks first (unless a fix is running).
    pub(super) fn open_repair(&mut self) {
        if !self.run.as_ref().is_some_and(|r| r.work.kind == Kind::Fix && r.running()) {
            self.begin(check_work(), 0);
        }
    }

    pub(super) fn repair_key(&mut self, key: Key) {
        match mode(self) {
            Mode::Stopped(run, at) if key == Key::Enter => {
                let work = run.work.clone();
                self.begin(work, at);
            }
            Mode::Failed(_) if key == Key::Enter => self.begin(check_work(), 0),
            Mode::Report(steps, _) => {
                let fix = steps.iter().any(|(_, s)| problem(s));
                let count = entries(&steps).len();
                if self.move_row(key, count) || key != Key::Enter {
                    return;
                }
                if fix && self.nav.row == 0 {
                    self.begin(fix_work(), 0);
                } else {
                    self.nav.row = 0;
                    self.begin(check_work(), 0);
                }
            }
            _ => {}
        }
    }
}
```

`maint/mod.rs`:
- Add `pub mod repair;`.
- `Page::Repair`: title "Repair"; help "It checks every step first; Fix N problems repairs, then checks again."
- `ENTRIES` becomes 6 entries, with `(Entry::Page(Page::Repair), "Repair")` second; `value` arm `"check every step, fix what is wrong"`.
- In `draw`, add `Page::Repair => repair::draw(…)`; in `open_page`, `Page::Repair => self.open_repair(),`; in `maint_key`, `Page::Repair => self.repair_key(key),`.
- `run_ended` adds the Fix result to the bar:

  ```rust
      pub(super) fn run_ended(&mut self) {
          self.files_changed();
          if let Some(run) = self.run.as_ref().filter(|r| r.work.kind == Kind::Fix && !r.running()) {
              let last = run.work.calls.len() - 1;
              if let Some(StepState::Done(out)) = &run.states[last] {
                  let left = repair::parse(out).iter().filter(|(_, s)| !s.finished()).count();
                  self.outcome = Some(match left {
                      0 => (true, format!("Repaired: everything is in order ({})", run.took())),
                      n => (false, format!("{n} problems left ({})", run.took())),
                  });
              }
          }
      }
  ```

  (with `use platform_host::StepState; use super::run::Kind;` at the top).

Then delete today's check and repair, as listed under **Files**.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin`
Expected: PASS.

- [ ] **Step 5: Docs and commit**

In `docs/components/openvibes-admin.md`:
- From the Maintenance › Setup paragraph, remove the `` `c` check … `r` repair … `` clauses.
- Add:

  > **Repair** (Maintenance): it asks for the password and checks every step first (`helper setup-status`), then lists the steps that need attention with why. The ones that pass fold into one line ("✓ 11 other steps in order"), since 14 do not fit 80×24. Fix N problems runs every step with `--repair` (never a new CA) on the worker, then checks again; the bar says what is left. A step that stops is marked ✗ with its error, and Try again goes on from it. Check again re-reads.

```bash
git add -A crates/openvibes-admin docs/components/openvibes-admin.md
git commit -m "TUI: Maintenance › Repair, a report first, then Fix N problems"
```

---

### Task 8: Uninstall leaves nothing behind (backend)

**Files:**
- Modify: `crates/platform-host/src/setup.rs`: `RemoveStep::Admin`, which comes last (name `admin`, title "Remove the administration tool"; `ALL` has 6).
- Modify: `crates/openvibes-admin/src/setup/remove.rs`:
  - `remove_admin`, and the `REPO` constant.
  - `run` gains the Admin arm; `job_end` moves from Purge to Admin.
  - `remove_packages` no longer tells the user to run `sudo dnf remove openvibes-admin`.
- Modify: `crates/openvibes-admin/src/setup/remove_tests.rs`:
  - The new tests.
  - `the_admin_package_is_left_for_last` asserts that the detail does not contain `sudo`.

**Interfaces:**
- Produces: `RemoveStep::Admin`, and `fn remove_admin<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String>`.

- [ ] **Step 1: Write the failing tests** (in `remove_tests.rs`)

```rust
const GPG: &str = "gpg-pubkey-7786da36-6a0f1e07\tOpenVIBES packages <26064407+itismelime@users.noreply.github.com> public key\n\
                   gpg-pubkey-11111111-1\tFedora (44) <fedora-44-primary@fedoraproject.org> public key\n";

fn admin_answers(fake: &Fake, left: &str) {
    fake.answer(&["/usr/bin/rpm", "-q", "--quiet", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/dnf", "remove", "-y", "openvibes-admin"], 0, "");
    fake.answer(&["/usr/bin/rpm", "-qa", "openvibes-*"], 0, left);
    fake.answer(&["/usr/bin/rpm", "-q", "gpg-pubkey"], 0, GPG);
    fake.answer(&["/usr/bin/rpm", "-e"], 0, "");
}

#[test]
fn the_last_step_removes_the_tool_what_rpm_kept_and_the_repository() {
    let fake = Fake::new("remove-admin-last");
    fake.file("/etc/openvibes/admin.toml.rpmsave", "x");
    fake.file("/var/lib/openvibes-admin/state", "x");
    fake.file("/etc/yum.repos.d/openvibes.repo", "[openvibes]\n");
    fake.file("/etc/yum.repos.d/fedora.repo", "[fedora]\n");
    admin_answers(&fake, "");
    let plan = plan(&[Ingest, Agent]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest, Agent], Some("platform.example.com")));
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    for gone in ["etc/openvibes", "var/lib/openvibes-admin", "etc/yum.repos.d/openvibes.repo"] {
        assert!(!fake.root.join(gone).exists(), "{gone} left behind");
    }
    assert!(fake.root.join("etc/yum.repos.d/fedora.repo").exists(), "not ours: kept");
    assert_eq!(fake.call(&["/usr/bin/rpm", "-e"]), ["/usr/bin/rpm", "-e", "gpg-pubkey-7786da36-6a0f1e07"]);
    assert!(!fake.called(&["/usr/bin/rpm", "-e", "gpg-pubkey-11111111-1"]), "Fedora's key stays");
}

#[test]
fn keep_data_removes_the_tool_and_keeps_the_configuration() {
    let fake = Fake::new("remove-admin-keep");
    fake.file("/etc/openvibes/setup.toml", "kept");
    admin_answers(&fake, "");
    let plan = plan(&[Ingest]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(matches!(state, StepState::Done(_)), "{state:?}");
    assert!(fake.called(&["/usr/bin/dnf", "remove", "-y", "openvibes-admin"]));
    assert_eq!(fake.text("/etc/openvibes/setup.toml"), "kept", "the data stays for a reinstall");
}

#[test]
fn removing_one_part_leaves_the_administration_tool() {
    let fake = Fake::new("remove-admin-part");
    let plan = plan(&[Ingest, Agent]);
    let state = run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Agent], None));
    assert!(matches!(state, StepState::Skipped(_)), "{state:?}");
    assert!(!fake.called(&["/usr/bin/dnf"]));
}

#[test]
fn the_repository_stays_while_another_openvibes_package_is_installed() {
    let fake = Fake::new("remove-admin-agent-left");
    fake.file("/etc/yum.repos.d/openvibes.repo", "[openvibes]\n");
    admin_answers(&fake, "openvibes-agent\n");
    let plan = plan(&[Ingest]);
    run(&fake.ctx(&plan), RemoveStep::Admin, &args(&[Ingest], None));
    assert!(fake.root.join("etc/yum.repos.d/openvibes.repo").exists());
    assert!(!fake.called(&["/usr/bin/rpm", "-e"]));
}
```

In `crates/platform-host/src/setup.rs`'s tests (or `tests/native.rs`):

```rust
#[test]
fn the_tool_itself_is_removed_last() {
    assert_eq!(RemoveStep::ALL.last(), Some(&RemoveStep::Admin));
    assert_eq!(RemoveStep::parse("admin"), Some(RemoveStep::Admin));
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin remove && cargo test -p platform-host the_tool_itself`
Expected: FAIL to compile (`RemoveStep::Admin`).

- [ ] **Step 3: Implement**

`platform-host/src/setup.rs`:
- `enum RemoveStep` gets `/// Last: the administration tool itself and its repository. Admin,`.
- `ALL: [RemoveStep; 6]` ends with `RemoveStep::Admin`.
- `name()` gets `RemoveStep::Admin => "admin"`, and `title()` gets `RemoveStep::Admin => "Remove the administration tool"`.

`setup/remove.rs`:
- The module doc's last sentence becomes "`openvibes-admin` itself is removed by the last step, `admin`: the running helper keeps its file open until it exits."
- In `remove_packages`, delete the `if args.components.contains(&Component::Ingest) { text.push_str(…sudo dnf remove…) }` block.
- Add:

```rust
/// The package repository install.sh writes (removed once no OpenVIBES
/// package is left).
const REPO: &str = "/etc/yum.repos.d/openvibes.repo";

/// Last: the administration tool itself (this helper is part of it; the
/// running process keeps its file until it exits), what rpm kept of it
/// (`admin.toml`, `.rpmsave`) and its state, and the package repository
/// and its signing key once no OpenVIBES package is left. Only for the
/// whole platform: removing one part leaves the tool.
fn remove_admin<R: Runner>(ctx: &Ctx<R>, args: &RemoveArgs) -> Result<StepState, String> {
    if !ctx.plan.components.iter().all(|c| args.components.contains(c)) {
        return Ok(StepState::Skipped("the administration tool stays: other parts remain".into()));
    }
    let mut done = Vec::new();
    if installed(ctx, "openvibes-admin") {
        ctx.ok(Dnf, &["remove", "-y", "openvibes-admin"])?;
        done.push("openvibes-admin");
    }
    if args.confirm.is_some() {
        for dir in ["/etc/openvibes", "/var/lib/openvibes-admin"] {
            let path = ctx.path(dir);
            if path.exists() {
                fs::remove_dir_all(&path).map_err(|error| format!("{dir}: {error}"))?;
            }
        }
        done.push("its configuration");
    }
    if ctx.ok(Rpm, &["-qa", "openvibes-*"])?.trim().is_empty() {
        if ctx.exists(REPO) {
            fs::remove_file(ctx.path(REPO)).map_err(|error| format!("{REPO}: {error}"))?;
            done.push("the package repository");
        }
        // Exit 1 when no key is installed: the output is what counts.
        let keys = ctx.stdout(Rpm, &["-q", "gpg-pubkey", "--qf", "%{NAME}-%{VERSION}-%{RELEASE}\t%{SUMMARY}\n"])?;
        for key in keys.lines().filter(|l| l.contains("OpenVIBES packages")).filter_map(|l| l.split('\t').next()) {
            ctx.ok(Rpm, &["-e", key])?;
            done.push("its signing key");
        }
    }
    Ok(StepState::Done(if done.is_empty() {
        "nothing left to remove".into()
    } else {
        format!("removed {}", done.join(", "))
    }))
}
```

In `run`, replace the last arms with:

```rust
        RemoveStep::Purge => purge(ctx, args),
        RemoveStep::Admin => remove_admin(ctx, args).inspect(|_| ctx.job_end()),
```

If a test asserts that the half-done mark is cleared after `Purge`, move its expectation to `Admin`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin && cargo test -p platform-host`
Expected: PASS. Today's change-components path (2a still has it) runs `remove-step admin` for one part, and gets Skipped.

- [ ] **Step 5: Docs and commit**

In `docs/components/openvibes-admin.md`, the `setup --uninstall` bullet's last sentence becomes:

> PostgreSQL stays (it may serve other programs). The last step, `admin`, removes `openvibes-admin` itself and, with `--everything`, what rpm kept of it (`/etc/openvibes`, including `admin.toml.rpmsave`) and `/var/lib/openvibes-admin`. Once no `openvibes-*` package is left, it also removes `/etc/yum.repos.d/openvibes.repo` and the OpenVIBES packages signing key. Nothing is left for the user to remove by hand; the root key file and backups in the user's folders are theirs and stay.

The verb list gains `remove-step admin`.

```bash
git add -A crates/platform-host crates/openvibes-admin docs/components/openvibes-admin.md
git commit -m "Uninstall removes the administration tool, its leftovers and the repository last"
```

---

### Task 9: Maintenance › Uninstall, and today's update and uninstall screens go

**Files:**
- Create: `crates/openvibes-admin/src/tui/maint/uninstall.rs` and `crates/openvibes-admin/src/tui/maint/uninstall_tests.rs`.
- Modify: `crates/openvibes-admin/src/tui/maint/mod.rs`:
  - `Page::Uninstall`, `Then::Uninstall`, and the entry "Uninstall" (last).
  - `Maint` fields `everything`, `typed`, `typing`, `typed_before` and `plan`.
  - `editing()` includes `typing`.
  - `half_done_problem` gets `"uninstall"`.
- Modify: `crates/openvibes-admin/src/tui/app.rs`: at the top of `key()`, after a successful uninstall, Enter or `q` quits and every other key does nothing.
- Delete:
  - `crates/openvibes-admin/src/tui/maintain.rs`, `crates/openvibes-admin/src/tui/maintain_view.rs` and `crates/openvibes-admin/src/tui/maintain_tests.rs`, with their `mod` lines in `tui/mod.rs`.
  - In `tui/setup.rs`: `Phase::Uninstall` with its `setup_key` arm, `Key::Char('x')`, and the fields `backup`, `confirm`, `everything` and `row2`, with their initialisers.
  - In `tui/setup_view.rs`: the `Phase::Uninstall` arm, the `maintain_view` import, and `x uninstall` in `RUN_KEYS` and `DONE_KEYS`.
  - In `tui/setup_tests.rs`: `remove_everything_needs_this_hosts_name` and `keep_data_uninstall_sends_no_confirmation`. Any test in `maintain_tests.rs` that is not about update or uninstall moves to `setup_tests.rs` first; `grep -n '#\[test\]' -A1 maintain_tests.rs` lists them.

**Interfaces:**
- Consumes: the folder (Task 5), `Memory` (Task 4), `RemoveStep::Admin` (Task 8), `App::begin` (Task 2), and `Plan` (`crate::setup::plan::Plan`).
- Produces:
  - `pub fn work(plan: &Plan, everything: bool, backup: Option<&str>) -> Work`.
  - `App::uninstall_key`, `App::uninstall_yes`, `App::open_uninstall` and `App::gone() -> bool`.

- [ ] **Step 1: Write the failing tests** (`maint/uninstall_tests.rs`)

```rust
//! Maintenance › Uninstall, key by key (maint4.py, backupdefault.py).

use crate::tui::{
    app::Key,
    maint::Page,
    nav::Screen,
    script_host::{screen, set_up, type_text},
};

const ALL: &str = "--components ingest,console,distribution,vulns,rules,agent --remember-choice";

#[test]
fn keep_the_data_is_the_default_and_back_up_first_is_off() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    let text = screen(&app);
    for want in ["(•) Keep the data", "( ) Remove everything", "[ ] Back up first", "PostgreSQL stays installed"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn remove_everything_needs_the_host_name_typed_exactly() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    assert!(screen(&app).contains("Nothing is left behind"));
    app.nav.row = 4; // Uninstall (Keep, Everything, Back up first, Type…, Uninstall)
    app.key(Key::Enter);
    assert!(app.question.is_none(), "no question before the name is typed");
    assert_eq!(app.nav.row, 3, "the name's row is highlighted");
    assert!(screen(&app).contains("Type platform.example.com to confirm"));
    app.key(Key::Enter);
    type_text(&mut app, "platform.example.co");
    assert!(!screen(&app).contains('✓'), "{}", screen(&app));
    type_text(&mut app, "m");
    assert!(screen(&app).contains('✓'));
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(screen(&app).contains("Remove OpenVIBES and all its data?"));
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let calls = app.host.calls.borrow().clone();
    assert_eq!(calls.len(), 6);
    assert_eq!(calls[0].0, format!("remove-step backup {ALL} --confirm platform.example.com"));
    assert_eq!(calls[5].0, format!("remove-step admin {ALL} --confirm platform.example.com"));
    let text = screen(&app);
    assert!(text.contains("OpenVIBES is removed from this host") && text.contains("Quit"), "{text}");
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Uninstall), "nothing is left to go back to");
    app.key(Key::Enter);
    assert!(app.quit);
}

#[test]
fn keep_the_data_sends_no_confirmation_and_says_where_the_data_is() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.nav.row = 3;
    app.key(Key::Enter);
    assert!(screen(&app).contains("Remove OpenVIBES?"));
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.host.calls.borrow()[0].0, format!("remove-step backup {ALL}"));
    assert!(screen(&app).contains("The data stays"));
}

#[test]
fn esc_cancels_the_typed_name_and_q_types_into_it() {
    let mut app = set_up(vec![]);
    app.open_page(Page::Uninstall);
    app.key(Key::Down);
    app.key(Key::Char(' '));
    app.nav.row = 3;
    app.key(Key::Enter);
    type_text(&mut app, "q?");
    assert_eq!(app.maint.typed, "q?");
    assert!(!app.quit);
    app.key(Key::Esc);
    assert_eq!(app.maint.typed, "");
    assert_eq!(app.nav.screen, Screen::Maint(Page::Uninstall));
}

#[test]
fn with_back_up_first_the_backup_goes_to_a_new_file_in_the_folder() {
    let dir = std::env::temp_dir().join(format!("ov-uninstall-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mut app = set_up(vec![]);
    let etc = app.root.join("etc/openvibes");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("backup.toml"), format!("folder = \"{}\"\nfirst = true\n", dir.display())).unwrap();
    app.open_page(Page::Uninstall);
    assert!(screen(&app).contains("Ticked because you backed up last time"));
    app.nav.row = 4; // Keep, Everything, Back up first, Save in folder, Uninstall
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let first = app.host.calls.borrow()[0].0.clone();
    let version = env!("CARGO_PKG_VERSION");
    assert!(first.contains(&format!("--backup {}/openvibes-{version}-", dir.display())), "{first}");
    std::fs::remove_dir_all(&dir).unwrap();
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin uninstall_tests`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `maint/uninstall.rs`**

```rust
//! Maintenance › Uninstall (spec §6; maint4.py, backupdefault.py): Keep
//! the data (default) or Remove everything (type the host name, ✓ when it
//! matches; nothing is left behind); Back up first as in Update; the
//! standard question. The tool removes itself last, so once it is done,
//! Enter quits.

use platform_host::{Host, RemoveStep, StepState};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{Then, failure, folder};
use crate::{
    setup::plan::Plan,
    tui::{
        app::{App, Key, Question},
        run::{Call, Kind, Run, Work},
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
            steps,
        },
    },
};

pub fn work(plan: &Plan, everything: bool, backup: Option<&str>) -> Work {
    let components: Vec<&str> = plan.components.iter().map(|c| c.name()).collect();
    let mut args = vec!["--components".to_owned(), components.join(","), "--remember-choice".to_owned()];
    if let Some(file) = backup {
        args.extend(["--backup".to_owned(), file.to_owned()]);
    }
    if everything {
        args.extend(["--confirm".to_owned(), plan.hostname.clone()]);
    }
    let calls = RemoveStep::ALL.iter().map(|s| Call::Remove(*s, args.clone())).collect();
    Work::new(Kind::Uninstall { everything }, calls)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Choice {
    Keep,
    Everything,
    First,
    Folder,
    Confirm,
    Go,
}

fn choices<H: Host>(app: &App<H>) -> Vec<Choice> {
    let mut out = vec![Choice::Keep, Choice::Everything, Choice::First];
    if app.maint.first {
        out.push(Choice::Folder);
    }
    if app.maint.everything {
        out.push(Choice::Confirm);
    }
    out.push(Choice::Go);
    out
}

fn uninstall_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run.as_ref().filter(|r| matches!(r.work.kind, Kind::Uninstall { .. }))
}

fn hostname<H: Host>(app: &App<H>) -> String {
    app.maint.plan.as_ref().map(|p| p.hostname.clone()).unwrap_or_default()
}

fn row<H: Host>(app: &App<H>, choice: Choice) -> Row {
    let t = &app.theme;
    let radio = |on: bool| if on { "(•)" } else { "( )" };
    match choice {
        Choice::Keep => Row::entry(&format!("{} Keep the data", radio(!app.maint.everything)), "remove the programs; data stays for a reinstall"),
        Choice::Everything => Row::entry(&format!("{} Remove everything", radio(app.maint.everything)), "programs, data, accounts, certificates, settings"),
        Choice::First => {
            let mark = if app.maint.first { Span::styled("[x]", t.green()) } else { Span::raw("[ ]") };
            let value = match (&app.maint.memory.folder, app.maint.first) {
                (_, true) => String::new(),
                (Some(folder), false) => folder.clone(),
                (None, false) => "no folder chosen yet".into(),
            };
            Row::Entry { name: vec![mark, Span::raw(" Back up first")], value: vec![Span::styled(value, t.dim())] }
        }
        Choice::Folder => Row::Entry { name: vec![Span::raw("Save in folder")], value: folder::value(t, &app.maint.folder) },
        Choice::Confirm => {
            let host = hostname(app);
            let mut value = vec![Span::raw(app.maint.typed.clone())];
            if app.maint.typing {
                value.push(Span::raw("█"));
            }
            if app.maint.typed == host && !host.is_empty() {
                value.push(Span::styled(" ✓", t.green()));
            }
            Row::Entry { name: vec![Span::raw(format!("Type {host} to confirm"))], value }
        }
        Choice::Go => Row::entry("Uninstall", ""),
    }
}

fn help<H: Host>(app: &App<H>, choice: Choice) -> Line<'static> {
    let t = &app.theme;
    let dim = |text: String| Line::styled(format!("    {text}"), t.dim());
    match choice {
        Choice::First if app.maint.memory.first => dim("Ticked because you backed up last time.".into()),
        Choice::First => dim("Off unless you chose it last time.".into()),
        Choice::Folder => folder::help(t, &app.maint.folder),
        Choice::Confirm => dim(format!("Type {} exactly; ✓ when it matches.", hostname(app))),
        _ if app.maint.everything => dim("Nothing is left behind: every account, file and firewall change goes.".into()),
        _ => dim("PostgreSQL stays installed; it may serve other programs.".into()),
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(run) = uninstall_run(app) {
        return draw_run(frame, head, app, run);
    }
    let t = &app.theme;
    let choices = choices(app);
    let chosen = choices.get(app.nav.row).copied();
    let host = hostname(app);
    let bar = match chosen {
        Some(Choice::Folder) if app.maint.folder.editing() => folder::bar(),
        Some(Choice::Folder) => Bar::keys(&[("Enter", "Choose a folder")]),
        Some(Choice::Confirm) if app.maint.typing => Bar::edit("Type the host name", &host, &[("Enter", "Done")]),
        Some(Choice::Confirm) => Bar::keys(&[("Enter", "Type the host name")]),
        Some(Choice::Go) => Bar::keys(&[("Enter", "Uninstall")]),
        _ => Bar::keys(&[("Space", "Select/deselect"), ("Enter", "Confirm")]),
    };
    let area = frame::draw(frame, t, head, Some("Uninstall"), &app.bar(bar));
    let rows: Vec<Row> = choices.iter().map(|c| row(app, *c)).collect();
    let height = u16::try_from(rows.len() * 2 + 1).unwrap_or(u16::MAX).min(area.height.saturating_sub(1));
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(t, &rows, app.nav.row, &mut scroll, height, 26);
    app.nav.scroll.set(scroll);
    if let Some(choice) = chosen {
        lines.push(help(app, choice));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_run<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let titles: Vec<String> = RemoveStep::ALL.iter().map(|s| s.title().to_owned()).collect();
    let bar = match run.current() {
        Some(i) => Bar::Busy { text: format!("Step {} of {}: {}", i + 1, titles.len(), titles[i]), tick: app.tick_count },
        None if run.ok() => Bar::only(&[("Enter", "Quit")]),
        None => Bar::act(&[("Enter", "Try again")]),
    };
    let area = frame::draw(frame, t, head, Some("Uninstalling"), &app.bar(bar));
    let mut lines = vec![Line::raw("")];
    lines.extend(steps::lines(t, &titles, &run.states, run.current(), app.tick_count, 6));
    lines.push(Line::raw(""));
    let Kind::Uninstall { everything } = run.work.kind else { return };
    if run.ok() {
        lines.push(Line::styled(format!("    ✓ OpenVIBES is removed from this host ({})", run.took()), t.green()));
        lines.push(Line::styled(
            if everything {
                "    Nothing is left behind. PostgreSQL stays installed; it may serve other programs."
            } else {
                "    The data stays in /etc/openvibes and /var/lib/openvibes-* for a reinstall."
            },
            t.dim(),
        ));
        if let Some(file) = run.work.calls.first().and_then(|c| match c {
            Call::Remove(_, args) => args.iter().position(|a| a == "--backup").and_then(|i| args.get(i + 1)),
            _ => None,
        }) {
            lines.push(Line::styled(format!("    Backup: {file}. Copy it off this host."), t.dim()));
        }
        if let Some(key) = app.maint.plan.as_ref().and_then(|p| p.root_key_out.as_ref()).filter(|_| everything) {
            lines.push(Line::styled(
                format!("    If you kept the root key file {}, it belongs to the old CA: delete it.", key.display()),
                t.dim(),
            ));
        }
    } else if let Some(at) = run.stopped_at() {
        let why = run.states[at].as_ref().map_or("", StepState::detail);
        let todo = if at == 0 { "Nothing was removed." } else { "OpenVIBES is partly removed: Try again finishes it." };
        lines.extend(failure(t, why, todo));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn open_uninstall(&mut self) {
        self.load_backup_choice();
        self.maint.everything = false;
        self.maint.typed.clear();
        self.maint.typing = false;
        self.maint.plan = match self.host.setup_plan().map_err(|e| e.to_string()).and_then(|text| toml::from_str::<Plan>(&text).map_err(|e| e.to_string())) {
            Ok(plan) => Some(plan),
            Err(error) => {
                self.outcome = Some((false, format!("the plan cannot be read: {error}")));
                None
            }
        };
    }

    /// After a successful uninstall nothing is left to go to.
    pub(super) fn gone(&self) -> bool {
        uninstall_run(self).is_some_and(Run::ok)
    }

    fn typed_key(&mut self, key: Key) {
        match key {
            Key::Char(c) if self.maint.typed.chars().count() < 255 => self.maint.typed.push(c),
            Key::Backspace => {
                self.maint.typed.pop();
            }
            Key::ClearLine => self.maint.typed.clear(),
            Key::Enter => self.maint.typing = false,
            Key::Esc => {
                self.maint.typing = false;
                self.maint.typed = std::mem::take(&mut self.maint.typed_before);
            }
            _ => {}
        }
    }

    pub(super) fn uninstall_key(&mut self, key: Key) {
        if self.maint.folder.editing() {
            return self.folder_key(key);
        }
        if self.maint.typing {
            return self.typed_key(key);
        }
        if let Some(run) = uninstall_run(self) {
            if !run.running() && !run.ok() && key == Key::Enter {
                let (work, at) = (run.work.clone(), run.stopped_at().unwrap_or(0));
                self.begin(work, at);
            }
            return;
        }
        let choices = choices(self);
        if self.move_row(key, choices.len()) {
            return;
        }
        match (choices.get(self.nav.row), key) {
            (Some(Choice::Keep), Key::Char(' ')) => self.maint.everything = false,
            (Some(Choice::Everything), Key::Char(' ')) => self.maint.everything = true,
            (Some(Choice::First), Key::Char(' ')) => self.maint.first = !self.maint.first,
            (Some(Choice::Folder), Key::Enter) => self.maint.folder.edit(),
            (Some(Choice::Confirm), Key::Enter) => {
                self.maint.typed_before = self.maint.typed.clone();
                self.maint.typing = true;
            }
            (Some(Choice::Keep | Choice::Everything | Choice::First | Choice::Go), Key::Enter) => self.ask_uninstall(),
            _ => {}
        }
    }

    fn ask_uninstall(&mut self) {
        let Some(plan) = &self.maint.plan else { return };
        let choices = choices(self);
        if self.maint.everything && self.maint.typed != plan.hostname {
            self.outcome = Some((false, format!("Type {} to confirm Remove everything", plan.hostname)));
            self.nav.row = choices.iter().position(|c| *c == Choice::Confirm).unwrap_or(0);
            return;
        }
        if self.maint.first && !self.maint.folder.ok() {
            self.outcome = Some((false, "Choose a folder for the backup first".into()));
            self.nav.row = choices.iter().position(|c| *c == Choice::Folder).unwrap_or(0);
            return;
        }
        let (text, detail) = match (self.maint.everything, self.maint.first) {
            (true, true) => ("Remove OpenVIBES and all its data?", "backup first"),
            (true, false) => ("Remove OpenVIBES and all its data?", "no backup"),
            (false, _) => ("Remove OpenVIBES?", "the data stays"),
        };
        self.question = Some((Question::Maint { text: text.into(), detail: detail.into(), then: Then::Uninstall }, true));
    }

    pub(super) fn uninstall_yes(&mut self) {
        let Some(plan) = self.maint.plan.clone() else { return };
        let file = self.maint.first.then(|| self.backup_file(env!("CARGO_PKG_VERSION")));
        self.begin(work(&plan, self.maint.everything, file.as_deref()), 0);
    }
}
```

`maint/mod.rs`:
- Add `pub mod uninstall;`.
- `Page::Uninstall`: title "Uninstall"; help "Space chooses Keep the data or Remove everything; Uninstall asks first."
- `Then::Uninstall`; `maint_yes` gets `Then::Uninstall => self.uninstall_yes(),`.
- `ENTRIES` becomes 7 entries, ending `(Entry::Page(Page::Uninstall), "Uninstall")`; `value` arm `"remove OpenVIBES from this host"`.
- In `draw`, add `Page::Uninstall => uninstall::draw(…)`; in `open_page`, `Page::Uninstall => self.open_uninstall(),`; in `maint_key`, `Page::Uninstall => self.uninstall_key(key),`.
- `Maint` gets:

  ```rust
      /// Uninstall: Remove everything instead of Keep the data.
      pub everything: bool,
      /// The host name typed to confirm Remove everything, while typing, and before.
      pub typed: String,
      pub typing: bool,
      pub typed_before: String,
      /// `setup.toml`, read when Uninstall opens.
      pub plan: Option<crate::setup::plan::Plan>,
  ```

  and `editing()` becomes `self.folder.editing() || self.typing`.
- `half_done_problem` gets `"uninstall" => ("An uninstall stopped half way", Page::Uninstall),`.
- Add `pub(super) fn gone_after_uninstall(&self) -> bool { self.gone() }` to the `impl App` there (the tui-level wrapper).

`app.rs` `key()`: first line after `self.outcome = None;`:

```rust
        // The tool removed itself: Enter (or q) quits, nothing else is left.
        if self.gone_after_uninstall() {
            if matches!(key, Key::Enter | Key::Char('q')) {
                self.quit = true;
            }
            return;
        }
```

(`Plan` must be `Clone`; it already derives `Clone`, as `repair_all` uses `plan.clone()`.)

Then delete, as listed under **Files**.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin`
Expected: PASS. Then run `wc -l crates/openvibes-admin/src/tui/*.rs crates/openvibes-admin/src/tui/maint/*.rs`. Every file is under 500 lines, except `setup.rs` and `setup_tests.rs`, which were over before and shrink here; note their sizes for 2b, which removes their set-up-host paths.

- [ ] **Step 5: Docs and commit**

In `docs/components/openvibes-admin.md`:
- Remove the `` `x` uninstall (…) `` clause and the "Only rows on screen take the focus…" sentence from the Maintenance › Setup paragraph. Rename that paragraph's subject from "Maintenance › Setup" to "Maintenance › Components and ports (today's Setup screen, until 2b)", keeping `m` and `p`.
- Add:

  > **Uninstall** (Maintenance): Keep the data (the default) or Remove everything, chosen with Space; Back up first as in Update; and Uninstall, which asks. Remove everything first needs this host's name (from `setup.toml`) typed exactly, with ✓ when it matches. The six remove steps run on the worker; the last one removes the administration tool itself, so once it is done Enter (or `q`) quits and nothing else is offered. The result says what stayed: the data for a reinstall (Keep), or nothing but PostgreSQL (Everything), and the backup file and the old root key file, which are the user's.

```bash
git add -A crates/openvibes-admin docs/components/openvibes-admin.md
git commit -m "TUI: Maintenance › Uninstall; today's update and uninstall screens go"
```

---

### Task 10: Docs, gate, a Fedora container uninstall, and a real terminal

**Files:**
- Modify: `docs/components/openvibes-admin.md` (a last pass over the "Administration TUI" section).

- [ ] **Step 1: The component page reads as one**

Read the whole "Administration TUI" section and check four things:
- It names the Maintenance entries in their order: Update OpenVIBES, Repair, Components and ports, Database, Back up, Settings files, Uninstall.
- Nothing still says `c`/`r`/`u`/`x`, "Database tab" or `sudo dnf remove openvibes-admin` (`grep -n 'sudo dnf remove\|Database tab\| c check\|x uninstall' docs/components/openvibes-admin.md` prints nothing).
- Its Tests line lists `run_tests.rs`, `maint/*_tests.rs` and `ui/steps.rs`.
- Commit any fix-up with the gate.

- [ ] **Step 2: The local gate**

Run the gate in `../testing.md` §2: `test-db.sh`, `build-console.sh`, fmt, `check-names.sh`, clippy `--all-features -- -D warnings -F unsafe-code`, doc, `cargo test --workspace --all-features`, and audit.
Expected: green, with `OPENVIBES_TEST_DATABASE_URL` set. Clippy must be clean: no item that an earlier task built is left unused.

- [ ] **Step 3: Nothing left behind, in a Fedora container** (`../testing.md` §3; never on this host)

```sh
set -e
podman run --rm -it -v "$PWD":/src:Z -w /src registry.fedoraproject.org/fedora:44 bash
# inside, follow ci.yml's "fedora" job (build the RPMs), then its "integration"
# job (install them, set up); then:
openvibes-admin setup --uninstall --everything --confirm "$(hostname)"
rpm -qa 'openvibes-*'                                  # expect: nothing
ls -d /etc/openvibes* /var/lib/openvibes-* 2>/dev/null # expect: nothing
getent passwd | grep -c openvibes || true              # expect: 0
test ! -e /etc/yum.repos.d/openvibes.repo
rpm -q gpg-pubkey --qf '%{SUMMARY}\n' | grep -c 'OpenVIBES packages' || true   # expect: 0
```

Expected: every check is empty or 0. If the integration job does not run systemd in the container, say so in the PR body and run the same checks on a lab VM (`openvibes-lab`, fresh Fedora 44).

- [ ] **Step 4: A real terminal at 80×24, compared with the mockups**

**Never confirm anything on this host: it is the user's production platform.** Answer No (`n`) to every question, and press Esc at every password prompt.

```sh
cargo build -q -p openvibes-admin
tmux new-session -d -s walk -x 80 -y 24 "target/debug/openvibes-admin"
tmux send-keys -t walk Down Enter            # Maintenance
tmux capture-pane -p -t walk                 # compare: home3.py / shell.py list
```

Walk with `send-keys` and capture each screen:
1. Update OpenVIBES: Space, then Enter on Save in folder. Type `/tmp`, then Tab (the browser), then Esc, then Esc. Down to Update now, Enter (the question), then `n`.
2. Repair: the password prompt shows; Esc.
3. Database: the report.
4. Back up: Enter, type `/nonexistent` (the check), Esc.
5. Settings files, then Esc.
6. Uninstall: Down, Space (Remove everything), Down to the name, Enter, type `wrong`, Enter; Enter on Uninstall shows "Type … to confirm"; Esc.
7. `?` (Help), then Esc, then `q`.

Repeat once with `TERM=linux NO_COLOR=1`. Compare each capture with `maint1.py`, `maint3.py`, `maint4.py`, `flows.py`, `backupfolder.py`, `backupdefault.py` and `general.py`, rendered with `python3 -I docs/specs/tui-rework/<page>.py docs/specs/tui-rework`. Check:
- one empty line under the location line;
- one empty line between entries;
- the value columns align;
- ⭡⭣ Move comes first in the bar;
- the help line sits under the list;
- no key is shown that does nothing.

Expected: matches. Save the Update, Repair and Uninstall captures for the PR.

- [ ] **Step 5: Commit**

```bash
git add docs/components/openvibes-admin.md
git commit -m "Docs: Maintenance pages of TUI sub-project 2a"
```

---

## Sub-project 2b (outline; its own plan follows 2a)

1. **Optional parts.**
   - Agent on this host and Assistant as checkboxes; Apply with the question ("Install the assistant? 2.7 GB").
   - It runs `setup-plan` (components changed, `--model fetch` when the assistant is added and its model is absent), then every step with `--repair`, then `remove-step … --components <unticked>`.
   - Backend: a removed part's data and account go too (`/var/lib/openvibes-llm` with its 2.7 GB model, `/etc/openvibes-agent`, `/var/lib/openvibes-agent`, the `openvibes-llm` and `openvibes_agent` accounts), so removing a part leaves nothing behind.
2. **Ports and addresses.**
   - Every port as an entry, edited in place and checked as typed (`listeners`, `ports::check_ports`): "18500 is free on this host".
   - Network devices 514/udp is an information row (the plan has no netlog port).
   - Apply says the consequence and runs `setup-plan` and then Repair (the moved-from ports close at Readiness).
3. **Certificates › Names.**
   - The report: expiry, names, signed by, intermediate (`Host::certificates`).
   - Names (host name, other names) edited through `setup-plan` and Repair.
   - Changing how certificates are issued stays for step 4.
4. **Console sign-in.**
   - Reset the admin password: a new password, shown once, to be changed at the next sign-in.
   - Backend: `user reset-password --password-stdin --must-change`; `console_auth::replace_password` gains `must_change`; a helper verb `admin-reset` / `Privileged::AdminReset`, whose password is asked in the bar.
   - No single sign-on row until step 7.
5. **Shell.**
   - The standard question, then the login password (verified through the helper, which writes the audit note).
   - Then `Host::shell()` hands over the terminal: the TUI restores it and runs the login shell of the operator (`SUDO_USER` under sudo, never root's), with the one line "type exit to go back to the menu".
   - `exit` comes back to Maintenance, with Shell highlighted.
   - A `clippy.toml` exception at its call site, with its reason (spec §10.9).
6. **Today's Setup screen goes for set-up hosts.**
   - `m`, `p`, `change_components`, `then_remove`, `previous*`, `jobs.rs` Repair/Remove, and "Components and ports".
   - #87 (a `setup.toml` left by a first install that stopped before the CA) opens the install form again, prefilled.
   - `setup.rs` and `setup_tests.rs` end under 500 lines.
7. Docs, gate, and the walk.
