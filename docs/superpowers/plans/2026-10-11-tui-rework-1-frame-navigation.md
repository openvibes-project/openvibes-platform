# TUI rework, sub-project 1: frame and navigation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The new TUI frame (block logo, location line, spaced scrolling lists, the key bar, questions, help) with the new Home, Status and Service screens on today's backend. Today's Setup, Configuration and Database screens stay reachable behind the new menu until sub-projects 2 and 3 replace them.

**Architecture:**
- **Frame primitives** live in `tui/ui/`: `theme`, `logo`, `bar`, `list` and `frame`. Every screen draws through them, so the spacing and bar rules hold everywhere.
- **Navigation** (`tui/nav.rs`) is a stack of `Screen` values; Esc pops, `?` pushes Help.
- **Legacy screens** (today's tabs) render under a one-line location header, with their own key handling. Navigation keys are filtered on the way in.
- **Status and Service** (`tui/status.rs`, `tui/service.rs`) replace the Services and Health tabs. A service action that is running is polled to its result through `App::tick(now)`.

**Tech Stack:** Rust 2024, ratatui 0.30 (already a dependency), `platform_host::Host` (unchanged).

**Spec:** `docs/specs/2026-10-10-tui-rework-design.md` (§1, §2, §4, §9, §11, §12 step 1). Mockups: `docs/specs/tui-rework/` — `round3.py`, `scroll.py`, `service2.py`, `home3.py`, `general.py`.

## Global Constraints

- Minimum 80×24. Smaller windows show only: `This window is W×H. OpenVIBES needs at least 80×24: make the window larger.`
- Logo: six rows of the approved block letters (`docs/specs/tui-rework/gen.py` `SHADOW_OPEN` / `SHADOW_VIBES`), starting at column 4. OPEN is white bold, VIBES is teal `#36b9e0` bold.
- Location line (row 7): `host · Screen › Sub` dim on the left. On the right: the version, dim, then, if an update exists, `▲ x.y.z available` in yellow. The right edge is column 76.
- Exactly one empty line after the location line. All content starts at column 4. The highlight `▸` is at column 2. The highlighted row has background `#1f3a4a` (reversed under `NO_COLOR`).
- Lists: one empty line between entries. Headings sit directly on their list. Scroll hints `⭡ N more` / `⭣ N more` (dim) occupy the gap line above the first and below the last visible entry, and count entries.
- Bar: three rows, a dim box. Keys are buttons (background `#30363d`, white bold; reversed under `NO_COLOR`). `⭡⭣ Move` comes first, except while a question is asked or a value is typed. Right side: `Esc Back  ?`; on Home: `q Quit  ?`.
- Questions: `question` in bold and `detail` dim on the left. On the right: `Yes` / `No` buttons (the chosen one highlighted), then `⭠⭢`, then `Enter Confirm`. `y`/`n` also answer and are not shown. Esc answers No.
- Arrows are `⭡⭣ ⭠⭢`, but `↑↓ ←→` when `TERM=linux`.
- No letter key is needed. Only `q` (Home) and `?` are shown.
- No "start at boot" switch. A service that is not enabled at boot is a problem with `Enter Fix`.
- Every file stays under 500 lines. The component page changes in the same change (Task 9).
- The local gate (`../testing.md`) must be green before the PR.

## Review Focus

1. **Esc inside a legacy screen while typing a value or answering y/n.** It must cancel the field or the prompt, not leave the screen and lose the edit. Test in Task 6.
2. **A service action whose unit never gets ready.** After 30 s the bar says it failed and why (the unit's last journal line), not a spinner forever. Test in Task 8.
3. **More services or problems than fit at 80×24.** The list scrolls one row per step, the counts follow, and the highlighted entry is always visible. Test in Task 4.
4. **`NO_COLOR` set.** Highlight and key buttons stay visible (reversed); no colour codes are written. Test in Task 1.
5. **A fresh host (not set up).** The TUI opens the legacy Setup form (the install screens come in sub-project 3), Esc there does nothing, and `q` still quits. Test in Task 6.

---

### Task 1: `ui::theme` — styles and glyphs

**Files:**
- Create: `crates/openvibes-admin/src/tui/ui/mod.rs`, `crates/openvibes-admin/src/tui/ui/theme.rs`
- Modify: `crates/openvibes-admin/src/tui/mod.rs` (add `mod ui;`)

**Interfaces:**
- Produces: `pub struct Theme { pub color: bool, pub plain_arrows: bool }` with `Theme::from_env() -> Theme`, `Theme::new(no_color: Option<&std::ffi::OsStr>, term: Option<&str>) -> Theme` and the styles `white()`, `teal()`, `dim()`, `bold()`, `green()`, `yellow()`, `red()`, `highlight()`, `key()`, `rule()` (all `-> ratatui::style::Style`). Glyphs: `up_down()`, `left_right()`, `up()`, `down()` (all `-> &'static str`). `pub const TEAL: Color`.

- [ ] **Step 1: Write the failing tests** (bottom of `ui/theme.rs`)

```rust
#[cfg(test)]
mod tests {
    use std::ffi::OsStr;

    use ratatui::style::{Color, Modifier};

    use super::*;

    #[test]
    fn arrows_are_plain_on_the_linux_console() {
        let fancy = Theme::new(None, Some("xterm-256color"));
        assert_eq!((fancy.up_down(), fancy.left_right()), ("⭡⭣", "⭠⭢"));
        let console = Theme::new(None, Some("linux"));
        assert_eq!((console.up_down(), console.left_right(), console.up(), console.down()), ("↑↓", "←→", "↑", "↓"));
    }

    #[test]
    fn no_color_keeps_highlight_and_keys_visible_without_colour() {
        let plain = Theme::new(Some(OsStr::new("1")), Some("xterm"));
        assert!(!plain.color);
        assert_eq!(plain.highlight().bg, None);
        assert!(plain.highlight().add_modifier.contains(Modifier::REVERSED));
        assert!(plain.key().add_modifier.contains(Modifier::REVERSED));
        assert_eq!(plain.teal().fg, None);
        let coloured = Theme::new(Some(OsStr::new("")), None);
        assert!(coloured.color, "an empty NO_COLOR means colour (no-color.org)");
        assert_eq!(coloured.teal().fg, Some(TEAL));
        assert_eq!(coloured.highlight().bg, Some(Color::Rgb(0x1f, 0x3a, 0x4a)));
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin ui::theme`
Expected: FAIL to compile, `cannot find type Theme`.

- [ ] **Step 3: Implement**

`ui/mod.rs`:

```rust
//! What every screen is drawn with (TUI rework spec §2): one theme, one
//! logo and location line, one bar, one list, one frame.

pub mod bar;
pub mod frame;
pub mod list;
pub mod logo;
pub mod theme;
```

(`bar`, `frame`, `list` and `logo` come in Tasks 2–5. Until each exists, add only `pub mod theme;` and add the others as their tasks create them.)

`ui/theme.rs`:

```rust
//! Colours, styles and glyphs every screen shares. Colour follows
//! no-color.org (`NO_COLOR` set and not empty: none); bold, dim and
//! reversed stay, so a highlight is still visible without colour.

use std::ffi::OsStr;

use ratatui::style::{Color, Modifier, Style};

/// The brand teal (middle of the brand gradient).
pub const TEAL: Color = Color::Rgb(0x36, 0xb9, 0xe0);
const HIGHLIGHT: Color = Color::Rgb(0x1f, 0x3a, 0x4a);
const KEY: Color = Color::Rgb(0x30, 0x36, 0x3d);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Theme {
    pub color: bool,
    /// The Linux text console has no ⭡⭣ glyphs: plain arrows there.
    pub plain_arrows: bool,
}

impl Theme {
    pub fn from_env() -> Self {
        Self::new(std::env::var_os("NO_COLOR").as_deref(), std::env::var("TERM").ok().as_deref())
    }

    pub fn new(no_color: Option<&OsStr>, term: Option<&str>) -> Self {
        Self {
            color: no_color.is_none_or(OsStr::is_empty),
            plain_arrows: term == Some("linux"),
        }
    }

    fn fg(&self, color: Color) -> Style {
        if self.color { Style::new().fg(color) } else { Style::new() }
    }

    pub fn white(&self) -> Style {
        self.fg(Color::White).add_modifier(Modifier::BOLD)
    }
    pub fn teal(&self) -> Style {
        self.fg(TEAL).add_modifier(Modifier::BOLD)
    }
    /// The header rule and box lines.
    pub fn rule(&self) -> Style {
        self.fg(TEAL)
    }
    pub fn dim(&self) -> Style {
        Style::new().add_modifier(Modifier::DIM)
    }
    pub fn bold(&self) -> Style {
        Style::new().add_modifier(Modifier::BOLD)
    }
    pub fn green(&self) -> Style {
        self.fg(Color::Green)
    }
    pub fn yellow(&self) -> Style {
        self.fg(Color::Yellow)
    }
    pub fn red(&self) -> Style {
        self.fg(Color::Red)
    }
    /// The highlighted row.
    pub fn highlight(&self) -> Style {
        if self.color {
            Style::new().bg(HIGHLIGHT).fg(Color::White)
        } else {
            Style::new().add_modifier(Modifier::REVERSED)
        }
    }
    /// A key shown as a button.
    pub fn key(&self) -> Style {
        if self.color {
            Style::new().bg(KEY).fg(Color::White).add_modifier(Modifier::BOLD)
        } else {
            Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD)
        }
    }

    pub fn up_down(&self) -> &'static str {
        if self.plain_arrows { "↑↓" } else { "⭡⭣" }
    }
    pub fn left_right(&self) -> &'static str {
        if self.plain_arrows { "←→" } else { "⭠⭢" }
    }
    pub fn up(&self) -> &'static str {
        if self.plain_arrows { "↑" } else { "⭡" }
    }
    pub fn down(&self) -> &'static str {
        if self.plain_arrows { "↓" } else { "⭣" }
    }
}
```

In `tui/mod.rs`, add `mod ui;` after `mod setup_view;`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin ui::theme && cargo clippy -p openvibes-admin --all-targets -- -D warnings`
Expected: PASS. The unused-code warnings will fail clippy until Task 6 uses the theme. If they do, put `#![allow(dead_code, reason = "used from Task 6 of the TUI rework plan")]` at the top of `ui/mod.rs` and remove it in Task 6.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/tui
git commit -m "TUI: theme (colour per NO_COLOR, arrows with a linux-console fallback)"
```

---

### Task 2: `ui::logo` — logo and location line

**Files:**
- Create: `crates/openvibes-admin/src/tui/ui/logo.rs`

**Interfaces:**
- Consumes: `Theme`.
- Produces:
  - `pub const ROWS: u16 = 7` (six logo rows plus the location line) and `pub const RIGHT: usize = 76`.
  - `pub struct Header<'a> { pub location: &'a str, pub version: &'a str, pub update: Option<&'a str> }`
  - `pub fn lines(theme: &Theme, header: &Header) -> Vec<Line<'static>>` (7 lines)
  - `pub fn location_line(theme: &Theme, header: &Header) -> Line<'static>` (the one-line header for legacy screens)
  - `pub fn text(lines: &[Line]) -> Vec<String>` (test helper: plain text of lines)

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn header(update: Option<&'static str>) -> Header<'static> {
        Header { location: "limebox · Maintenance › Certificates", version: "v0.2.8", update }
    }

    #[test]
    fn six_logo_rows_then_the_location_line_ending_at_column_76() {
        let theme = Theme::new(None, None);
        let text = text(&lines(&theme, &header(Some("0.2.9"))));
        assert_eq!(text.len(), 7);
        assert!(text[0].starts_with("     ██████╗ ██████╗"), "{:?}", text[0]);
        assert!(text[6].starts_with("    limebox · Maintenance › Certificates"));
        assert!(text[6].ends_with("v0.2.8  ▲ 0.2.9 available"), "{:?}", text[6]);
        assert_eq!(text[6].chars().count(), RIGHT);
    }

    #[test]
    fn no_update_shows_only_the_version() {
        let theme = Theme::new(None, None);
        let text = text(&lines(&theme, &header(None)));
        assert!(text[6].ends_with("v0.2.8") && !text[6].contains("available"));
        assert_eq!(text[6].chars().count(), RIGHT);
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin ui::logo`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `ui/logo.rs`** (add `pub mod logo;` to `ui/mod.rs`)

```rust
//! The approved logo (block letters, OPEN white, VIBES teal) and the
//! location line under it: where you are on the left, the version and any
//! available update on the right (spec §2).

use ratatui::text::{Line, Span};

use super::theme::Theme;

pub const ROWS: u16 = 7;
/// The column the location line ends at (the logo's right edge).
pub const RIGHT: usize = 76;
const INDENT: &str = "    ";

const OPEN: [&str; 6] = [
    " ██████╗ ██████╗ ███████╗███╗   ██╗",
    "██╔═══██╗██╔══██╗██╔════╝████╗  ██║",
    "██║   ██║██████╔╝█████╗  ██╔██╗ ██║",
    "██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║",
    "╚██████╔╝██║     ███████╗██║ ╚████║",
    " ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝",
];
const VIBES: [&str; 6] = [
    "██╗   ██╗██╗██████╗ ███████╗███████╗",
    "██║   ██║██║██╔══██╗██╔════╝██╔════╝",
    "██║   ██║██║██████╔╝█████╗  ███████╗",
    "╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════██║",
    " ╚████╔╝ ██║██████╔╝███████╗███████║",
    "  ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚══════╝",
];

pub struct Header<'a> {
    pub location: &'a str,
    pub version: &'a str,
    pub update: Option<&'a str>,
}

pub fn location_line(theme: &Theme, header: &Header) -> Line<'static> {
    let mut right = vec![Span::styled(header.version.to_owned(), theme.dim())];
    let mut right_len = header.version.chars().count();
    if let Some(update) = header.update {
        let notice = format!("  ▲ {update} available");
        right_len += notice.chars().count();
        right.push(Span::styled(notice, theme.yellow()));
    }
    let left = header.location.chars().count();
    let gap = RIGHT.saturating_sub(INDENT.len() + left + right_len).max(1);
    let mut spans = vec![
        Span::raw(INDENT),
        Span::styled(header.location.to_owned(), theme.dim()),
        Span::raw(" ".repeat(gap)),
    ];
    spans.extend(right);
    Line::from(spans)
}

pub fn lines(theme: &Theme, header: &Header) -> Vec<Line<'static>> {
    let mut out: Vec<Line> = OPEN
        .iter()
        .zip(VIBES)
        .map(|(open, vibes)| {
            Line::from(vec![
                Span::raw(INDENT),
                Span::styled(*open, theme.white()),
                Span::styled(vibes, theme.teal()),
            ])
        })
        .collect();
    out.push(location_line(theme, header));
    out
}

/// The plain text of `lines` (tests).
pub fn text(lines: &[Line]) -> Vec<String> {
    lines
        .iter()
        .map(|line| line.spans.iter().map(|span| span.content.as_ref()).collect())
        .collect()
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin ui::logo`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/tui/ui
git commit -m "TUI: block logo and the location line (version, update notice)"
```

---

### Task 3: `ui::bar` — the key bar, questions, typing, work

**Files:**
- Create: `crates/openvibes-admin/src/tui/ui/bar.rs`

**Interfaces:**
- Consumes: `Theme`.
- Produces:
  - `pub enum Bar { Keys { keys: Vec<(String, String)>, nav: bool, home: bool }, Ask { question: String, detail: String, yes: bool }, Typing { label: String, shown: String, done: String }, Busy { text: String, tick: usize }, Done { ok: bool, text: String } }`
  - `impl Bar { pub fn keys(keys: &[(&str, &str)]) -> Bar; pub fn home(keys: &[(&str, &str)]) -> Bar; pub fn lines(&self, theme: &Theme, width: u16) -> [Line<'static>; 3] }`
  - `pub const HEIGHT: u16 = 3`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::ui::logo::text;

    fn plain() -> Theme {
        Theme::new(None, Some("xterm"))
    }

    #[test]
    fn keys_start_with_move_and_end_with_back_and_help() {
        let bar = Bar::keys(&[("Enter", "Restart ingest")]);
        let t = text(&bar.lines(&plain(), 80));
        assert_eq!(t[0], format!(" ┌{}┐", "─".repeat(76)));
        assert!(t[1].starts_with(" │  ⭡⭣  Move   Enter  Restart ingest"), "{:?}", t[1]);
        assert!(t[1].ends_with("  Esc  Back    ?  │"), "{:?}", t[1]);
        assert_eq!(t[1].chars().count(), 79);
    }

    #[test]
    fn home_offers_quit_instead_of_back() {
        let t = text(&Bar::home(&[("Enter", "Open")]).lines(&plain(), 80));
        assert!(t[1].ends_with("  q  Quit    ?  │") && !t[1].contains("Back"), "{:?}", t[1]);
    }

    #[test]
    fn a_question_has_buttons_arrows_and_enter_confirm_and_no_move() {
        let bar = Bar::Ask { question: "Restart ingest?".into(), detail: "agents reconnect".into(), yes: true };
        let t = text(&bar.lines(&plain(), 80));
        assert!(t[1].starts_with(" │ Restart ingest? agents reconnect"), "{:?}", t[1]);
        assert!(t[1].contains(" Yes  [ No ]   ⭠⭢   Enter  Confirm"), "{:?}", t[1]);
        assert!(!t[1].contains("Move"));
    }

    #[test]
    fn busy_and_done_say_what_happens() {
        let t = text(&Bar::Busy { text: "Restarting ingest…".into(), tick: 0 }.lines(&plain(), 80));
        assert!(t[1].starts_with(" │ ⠋ Restarting ingest…"), "{:?}", t[1]);
        let t = text(&Bar::Done { ok: true, text: "ingest restarted and ready (4 s)".into() }.lines(&plain(), 80));
        assert!(t[1].starts_with(" │ ✓ ingest restarted and ready (4 s)"), "{:?}", t[1]);
        let t = text(&Bar::Done { ok: false, text: "ingest did not start".into() }.lines(&plain(), 80));
        assert!(t[1].starts_with(" │ ✗ ingest did not start"));
    }

    #[test]
    fn plain_arrows_on_the_linux_console() {
        let t = text(&Bar::keys(&[]).lines(&Theme::new(None, Some("linux")), 80));
        assert!(t[1].contains(" ↑↓  Move"), "{:?}", t[1]);
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin ui::bar`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `ui/bar.rs`** (add `pub mod bar;`)

```rust
//! The bottom bar (spec §2): a dim box, one line inside. Keys are buttons;
//! ⭡⭣ Move comes first unless a question is asked or a value typed; Esc
//! Back and ? sit at the right (q Quit and ? on Home). Questions, typing
//! and running work take the bar's place.

use ratatui::text::{Line, Span};

use super::theme::Theme;

pub const HEIGHT: u16 = 3;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bar {
    Keys { keys: Vec<(String, String)>, nav: bool, home: bool },
    Ask { question: String, detail: String, yes: bool },
    /// A value being typed: what it is, how it shows (masked for a
    /// password), what Enter does.
    Typing { label: String, shown: String, done: String },
    Busy { text: String, tick: usize },
    Done { ok: bool, text: String },
}

impl Bar {
    pub fn keys(keys: &[(&str, &str)]) -> Bar {
        Bar::Keys { keys: owned(keys), nav: true, home: false }
    }
    pub fn home(keys: &[(&str, &str)]) -> Bar {
        Bar::Keys { keys: owned(keys), nav: true, home: true }
    }

    pub fn lines(&self, theme: &Theme, width: u16) -> [Line<'static>; 3] {
        let inner = usize::from(width.saturating_sub(4));
        let (left, right) = self.parts(theme);
        let used: usize = left.iter().chain(&right).map(|s| s.content.chars().count()).sum();
        let mut spans = vec![Span::raw(" "), Span::styled("│", theme.dim()), Span::raw(" ")];
        spans.extend(left);
        spans.push(Span::raw(" ".repeat(inner.saturating_sub(used + 1).max(1))));
        spans.extend(right);
        spans.push(Span::raw(" "));
        spans.push(Span::styled("│", theme.dim()));
        let rule = "─".repeat(usize::from(width.saturating_sub(4)));
        [
            Line::from(vec![Span::raw(" "), Span::styled(format!("┌{rule}┐"), theme.dim())]),
            Line::from(spans),
            Line::from(vec![Span::raw(" "), Span::styled(format!("└{rule}┘"), theme.dim())]),
        ]
    }

    fn parts(&self, theme: &Theme) -> (Vec<Span<'static>>, Vec<Span<'static>>) {
        let key = |k: &str, label: &str| {
            vec![Span::styled(format!(" {k} "), theme.key()), Span::raw(format!(" {label}   "))]
        };
        match self {
            Bar::Keys { keys, nav, home } => {
                let mut left = Vec::new();
                if *nav {
                    left.extend(key(theme.up_down(), "Move"));
                }
                for (k, label) in keys {
                    left.extend(key(k, label));
                }
                let mut right = if *home { key("q", "Quit") } else { key("Esc", "Back") };
                right.push(Span::styled(" ? ", theme.key()));
                (left, right)
            }
            Bar::Ask { question, detail, yes } => {
                let left = vec![
                    Span::styled(question.clone(), theme.bold()),
                    Span::raw(" "),
                    Span::styled(detail.clone(), theme.dim()),
                ];
                let (y, n) = if *yes { (theme.highlight(), theme.dim()) } else { (theme.dim(), theme.highlight()) };
                let mut right = vec![
                    Span::styled(if *yes { " Yes " } else { "[ Yes ]" }.to_owned(), y),
                    Span::raw(" "),
                    Span::styled(if *yes { "[ No ]" } else { " No " }.to_owned(), n),
                    Span::raw("  "),
                ];
                right.extend(key(theme.left_right(), "").into_iter().take(1));
                right.push(Span::raw("  "));
                right.push(Span::styled(" Enter ", theme.key()));
                right.push(Span::raw(" Confirm"));
                (left, right)
            }
            Bar::Typing { label, shown, done } => {
                let mut left = vec![Span::styled(format!("{label}: "), theme.bold()), Span::raw(format!("{shown}█  "))];
                left.extend(key("Enter", done));
                (left, key("Esc", "Cancel").into_iter().map(trim_end).collect())
            }
            Bar::Busy { text, tick } => (
                vec![Span::styled(SPINNER[tick % SPINNER.len()].to_owned(), theme.teal()), Span::raw(format!(" {text}"))],
                Vec::new(),
            ),
            Bar::Done { ok, text } => (
                vec![
                    if *ok { Span::styled("✓", theme.green()) } else { Span::styled("✗", theme.red()) },
                    Span::raw(format!(" {text}")),
                ],
                Vec::new(),
            ),
        }
    }
}

fn owned(keys: &[(&str, &str)]) -> Vec<(String, String)> {
    keys.iter().map(|(k, l)| ((*k).to_owned(), (*l).to_owned())).collect()
}

/// A trailing label without its gap (the last thing on the right).
fn trim_end(span: Span<'static>) -> Span<'static> {
    Span { content: span.content.trim_end().to_owned().into(), style: span.style }
}
```

The key/label gaps are three spaces between groups. The right group ends `… Back    ? ` (the `?` button is `" ? "`). If a test's exact spacing disagrees with this code, **fix the code to match the test**: the test strings follow the approved mockups. Then run the test again.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin ui::bar`
Expected: PASS once the spacing matches the tests.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/tui/ui
git commit -m "TUI: the bar (keys as buttons, Move first, questions, typing, work)"
```

---

### Task 4: `ui::list` — spaced, scrolling lists with headings

**Files:**
- Create: `crates/openvibes-admin/src/tui/ui/list.rs`

**Interfaces:**
- Consumes: `Theme`.
- Produces:
  - `pub enum Row { Heading { text: String, right: String }, Entry { name: Vec<Span<'static>>, value: Vec<Span<'static>> } }`
  - `impl Row { pub fn entry(name: &str, value: &str) -> Row }`
  - `pub struct Scroll { pub top: usize }` (`Default`)
  - `pub fn lines(theme: &Theme, rows: &[Row], selected: usize, scroll: &mut Scroll, height: u16, name_w: usize) -> Vec<Line<'static>>` (`selected` counts entries only)
  - `pub fn entries(rows: &[Row]) -> usize`

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::ui::logo::text;

    fn theme() -> Theme {
        Theme::new(None, Some("xterm"))
    }

    fn rows(n: usize) -> Vec<Row> {
        (0..n).map(|i| Row::entry(&format!("item{i}"), &format!("value {i}"))).collect()
    }

    #[test]
    fn one_empty_line_between_entries_and_the_highlight_at_column_two() {
        let mut scroll = Scroll::default();
        let t = text(&lines(&theme(), &rows(3), 1, &mut scroll, 13, 15));
        assert_eq!(t[0], "", "the gap above the first entry");
        assert_eq!(t[1].trim_end(), "    item0           value 0");
        assert_eq!(t[2], "");
        assert!(t[3].starts_with("  ▸ item1           value 1"), "{:?}", t[3]);
        assert_eq!(t[4], "");
        assert_eq!(t[5].trim_end(), "    item2           value 2");
    }

    #[test]
    fn a_heading_sits_directly_on_its_list() {
        let rows = vec![
            Row::Heading { text: "Services".into(), right: "8 of 8 running".into() },
            Row::entry("ingest", "running"),
        ];
        let mut scroll = Scroll::default();
        let t = text(&lines(&theme(), &rows, 0, &mut scroll, 13, 15));
        assert!(t[1].starts_with("    Services") && t[1].trim_end().ends_with("8 of 8 running"), "{:?}", t[1]);
        assert!(t[2].starts_with("  ▸ ingest"));
    }

    #[test]
    fn scrolling_moves_one_row_and_the_counts_follow() {
        let rows = rows(8);
        let mut scroll = Scroll::default();
        // 11 lines: a gap/hint line, five entries with gaps (9), a hint line.
        let t = text(&lines(&theme(), &rows, 4, &mut scroll, 11, 15));
        assert_eq!(t[0], "");
        assert!(t[9].starts_with("  ▸ item4"));
        assert_eq!(t[10].trim_end(), "    ⭣ 3 more");
        let t = text(&lines(&theme(), &rows, 5, &mut scroll, 11, 15));
        assert_eq!(t[0].trim_end(), "    ⭡ 1 more");
        assert!(t[9].starts_with("  ▸ item5"));
        assert_eq!(t[10].trim_end(), "    ⭣ 2 more");
        let t = text(&lines(&theme(), &rows, 7, &mut scroll, 11, 15));
        assert_eq!(t[0].trim_end(), "    ⭡ 3 more");
        assert_eq!(t[10], "");
        let t = text(&lines(&theme(), &rows, 2, &mut scroll, 11, 15));
        assert!(t.iter().any(|l| l.starts_with("  ▸ item2")), "going up scrolls back: {t:?}");
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin ui::list`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `ui/list.rs`** (add `pub mod list;`)

```rust
//! The one list every screen uses (spec §2): an empty line between
//! entries, headings directly on their list, a highlighted entry, and
//! scrolling one row per step with "⭡ N more" / "⭣ N more" in the gap
//! lines above the first and below the last visible entry.

use ratatui::text::{Line, Span};

use super::theme::Theme;

#[derive(Clone, Debug)]
pub enum Row {
    Heading { text: String, right: String },
    Entry { name: Vec<Span<'static>>, value: Vec<Span<'static>> },
}

impl Row {
    pub fn entry(name: &str, value: &str) -> Row {
        Row::Entry { name: vec![Span::raw(name.to_owned())], value: vec![Span::raw(value.to_owned())] }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Scroll {
    /// The first laid-out line shown.
    pub top: usize,
}

pub fn entries(rows: &[Row]) -> usize {
    rows.iter().filter(|r| matches!(r, Row::Entry { .. })).count()
}

fn width(spans: &[Span]) -> usize {
    spans.iter().map(|s| s.content.chars().count()).sum()
}

/// Every row laid out: the line, and which entry it is (if one).
fn layout(theme: &Theme, rows: &[Row], selected: usize, name_w: usize) -> Vec<(Line<'static>, Option<usize>)> {
    let mut out = Vec::new();
    let mut entry = 0;
    let mut last_was_entry = false;
    for (i, row) in rows.iter().enumerate() {
        match row {
            Row::Heading { text, right } => {
                if i > 0 {
                    out.push((Line::raw(""), None));
                }
                let gap = 72usize.saturating_sub(4 + text.chars().count() + right.chars().count()).max(1);
                out.push((
                    Line::from(vec![
                        Span::raw("    "),
                        Span::styled(text.clone(), theme.bold()),
                        Span::raw(" ".repeat(gap)),
                        Span::styled(right.clone(), theme.dim()),
                    ]),
                    None,
                ));
                last_was_entry = false;
            }
            Row::Entry { name, value } => {
                if last_was_entry {
                    out.push((Line::raw(""), None));
                }
                let pad = " ".repeat(name_w.saturating_sub(width(name)) + 1);
                let mut spans = Vec::new();
                if entry == selected {
                    spans.push(Span::styled("  ▸ ", theme.highlight()));
                    spans.extend(name.iter().map(|s| Span::styled(s.content.clone(), theme.highlight())));
                    spans.push(Span::styled(pad, theme.highlight()));
                    let tail = 72usize.saturating_sub(4 + name_w + 1 + width(value));
                    spans.extend(value.iter().map(|s| Span::styled(s.content.clone(), theme.highlight())));
                    spans.push(Span::styled(" ".repeat(tail), theme.highlight()));
                } else {
                    spans.push(Span::raw("    "));
                    spans.extend(name.iter().cloned());
                    spans.push(Span::raw(pad));
                    spans.extend(value.iter().map(|s| Span::styled(s.content.clone(), s.style.patch(theme.dim()))));
                }
                out.push((Line::from(spans), Some(entry)));
                entry += 1;
                last_was_entry = true;
            }
        }
    }
    out
}

pub fn lines(theme: &Theme, rows: &[Row], selected: usize, scroll: &mut Scroll, height: u16, name_w: usize) -> Vec<Line<'static>> {
    let laid = layout(theme, rows, selected, name_w);
    let inner = usize::from(height).saturating_sub(2).max(1);
    let at = laid.iter().position(|(_, e)| *e == Some(selected)).unwrap_or(0);
    if at < scroll.top {
        scroll.top = at;
    } else if at >= scroll.top + inner {
        scroll.top = at + 1 - inner;
    }
    scroll.top = scroll.top.min(laid.len().saturating_sub(inner));
    let window = &laid[scroll.top..(scroll.top + inner).min(laid.len())];
    let above = laid[..scroll.top].iter().filter(|(_, e)| e.is_some()).count();
    let below = laid[(scroll.top + window.len())..].iter().filter(|(_, e)| e.is_some()).count();
    let hint = |n: usize, arrow: &str| {
        if n == 0 {
            Line::raw("")
        } else {
            Line::from(vec![Span::raw("    "), Span::styled(format!("{arrow} {n} more"), theme.dim())])
        }
    };
    let mut out = vec![hint(above, theme.up())];
    out.extend(window.iter().map(|(l, _)| l.clone()));
    out.push(hint(below, theme.down()));
    out
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin ui::list`
Expected: PASS. If the hint line moves because a window starts on a gap line, keep the window on the line positions the test expects (adjust the `scroll.top` clamp so it never starts on a gap line directly above an entry). The tests are the contract.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/tui/ui
git commit -m "TUI: the list (spaced, headings, one-row scrolling with counts)"
```

---

### Task 5: `ui::frame` — one frame for every screen

**Files:**
- Create: `crates/openvibes-admin/src/tui/ui/frame.rs`

**Interfaces:**
- Consumes: `logo::{lines, Header, ROWS}`, `Bar`, `Theme`.
- Produces:
  - `pub fn too_small(frame: &mut Frame) -> bool` (draws the sentence and returns true below 80×24)
  - `pub fn draw(frame: &mut Frame, theme: &Theme, header: &Header, title: Option<&str>, bar: &Bar) -> Rect` (draws logo, location line, gap, optional title rule plus gap, and the bar; returns the content area)
  - `pub fn legacy(frame: &mut Frame, theme: &Theme, header: &Header) -> Rect` (one location line, then the rest)

- [ ] **Step 1: Write the failing tests**

```rust
#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::tui::ui::logo::Header;

    fn render(w: u16, h: u16, title: Option<&str>) -> (Vec<String>, Rect) {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        let mut area = Rect::default();
        terminal
            .draw(|f| {
                if !too_small(f) {
                    let header = Header { location: "limebox · Status", version: "v0.2.8", update: None };
                    area = draw(f, &Theme::new(None, Some("xterm")), &header, title, &Bar::keys(&[]));
                }
            })
            .unwrap();
        let b = terminal.backend().buffer();
        let rows = (0..b.area.height)
            .map(|y| (0..b.area.width).map(|x| b[(x, y)].symbol()).collect::<String>())
            .collect();
        (rows, area)
    }

    #[test]
    fn logo_location_one_empty_line_then_the_title_and_one_more() {
        let (rows, area) = render(80, 24, Some("Status"));
        assert!(rows[6].starts_with("    limebox · Status"));
        assert_eq!(rows[7].trim(), "", "exactly one empty line under the location line");
        assert!(rows[8].starts_with("    ━━ Status ━━"), "{:?}", rows[8]);
        assert_eq!(rows[9].trim(), "");
        assert_eq!(area.y, 10);
        assert_eq!(area.height, 24 - 10 - 3);
        assert!(rows[22].contains("Move"));
    }

    #[test]
    fn a_small_window_gets_one_sentence() {
        let (rows, _) = render(60, 18, None);
        let all = rows.join("\n");
        assert!(all.contains("This window is 60×18."), "{all}");
        assert!(all.contains("OpenVIBES needs at least 80×24:"));
    }
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin ui::frame`
Expected: FAIL to compile.

- [ ] **Step 3: Implement `ui/frame.rs`** (add `pub mod frame;`)

```rust
//! One frame for every screen (spec §2): logo, location line, exactly one
//! empty line, an optional title rule and one more empty line, the
//! content, and the bar. Legacy screens get only the location line.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{bar::{self, Bar}, logo::{self, Header}, theme::Theme};

pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;

pub fn too_small(frame: &mut Frame) -> bool {
    let area = frame.area();
    if area.width >= MIN_WIDTH && area.height >= MIN_HEIGHT {
        return false;
    }
    let lines = vec![
        Line::raw(format!("This window is {}×{}.", area.width, area.height)),
        Line::raw(format!("OpenVIBES needs at least {MIN_WIDTH}×{MIN_HEIGHT}:")),
        Line::raw("make the window larger."),
    ];
    let top = area.height.saturating_sub(3) / 2;
    let rect = Rect { y: area.y + top, height: 3.min(area.height), ..area };
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), rect);
    true
}

pub fn draw(frame: &mut Frame, theme: &Theme, header: &Header, title: Option<&str>, bar: &Bar) -> Rect {
    let area = frame.area();
    let heading = if title.is_some() { 2 } else { 0 };
    let [top, _gap, head, content, bottom] = Layout::vertical([
        Constraint::Length(logo::ROWS),
        Constraint::Length(1),
        Constraint::Length(heading),
        Constraint::Min(0),
        Constraint::Length(bar::HEIGHT),
    ])
    .areas(area);
    frame.render_widget(Paragraph::new(logo::lines(theme, header)), top);
    if let Some(title) = title {
        let rule = "━".repeat(70usize.saturating_sub(title.chars().count()));
        let line = Line::from(vec![
            Span::raw("    "),
            Span::styled("━━ ", theme.rule()),
            Span::styled(title.to_owned(), theme.bold()),
            Span::styled(format!(" {rule}"), theme.rule()),
        ]);
        frame.render_widget(Paragraph::new(vec![line, Line::raw("")]), head);
    }
    frame.render_widget(Paragraph::new(bar.lines(theme, area.width).to_vec()), bottom);
    content
}

pub fn legacy(frame: &mut Frame, theme: &Theme, header: &Header) -> Rect {
    let area = frame.area();
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    frame.render_widget(Paragraph::new(logo::location_line(theme, header)), top);
    rest
}
```

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin ui::frame`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/openvibes-admin/src/tui/ui
git commit -m "TUI: one frame for every screen; one sentence for a small window"
```

---

### Task 6: Navigation, Home, and today's screens behind the menu

**Files:**
- Create: `crates/openvibes-admin/src/tui/nav.rs`, `crates/openvibes-admin/src/tui/home.rs`, `crates/openvibes-admin/src/tui/nav_tests.rs`
- Modify: `crates/openvibes-admin/src/tui/app.rs` (fields `theme`, `nav`, `update`, `pending`, `outcome`, `question`, `prompt`; `App::new` starting screen; `key()` routing through `nav`; `open()` sets `Screen::Legacy`)
- Modify: `crates/openvibes-admin/src/tui/mod.rs` (render through `nav::render`; remove the banner; loop calls `app.tick(Instant::now())`)
- Modify: `crates/openvibes-admin/src/tui/setup.rs` (`form_key`: `Key::Esc` on a set-up host's form → `Phase::Status`)
- Delete: `crates/openvibes-admin/src/tui/banner.rs`, `crates/openvibes-admin/src/tui/banner_tests.rs`
- Modify tests that switched screens with Tab: in `setup_tests.rs`, `maintain_tests.rs` and `database_tests.rs`, replace `app.tab = Tab::Setup;` with `app.open(Tab::Setup);`. Replace each `app.key(Key::Tab)` / `Key::BackTab` used to reach a screen with the `app.open(Tab::…)` of the screen it reached. Replace `setup_tests.rs:164`'s `assert_eq!(app(true, vec![]).tab, Tab::Services)` with `assert_eq!(app(true, vec![]).nav.screen, Screen::Home)`. In `tests.rs`, `configuration()` becomes `{ let mut app = app(refuse); app.open(Tab::Configuration); app }`. `tab_switches_screens` is deleted (navigation is tested in `nav_tests.rs`).

**Interfaces:**
- Consumes: `ui::*`.
- Produces:
  - In `nav.rs`: `#[derive(Clone, Debug, Eq, PartialEq)] pub enum Screen { Home, Status, Service(Unit), Log(Unit), Maintenance, Help(Box<Screen>), Legacy }` and `pub struct Nav { pub screen: Screen, pub back: Vec<Screen>, pub row: usize, pub scroll: Scroll }`.
  - Methods on `Nav`: `go(&mut self, to: Screen)` (push), `pop(&mut self) -> bool`.
  - Free functions: `nav::render<H: Host>(frame: &mut Frame, app: &App<H>)` and `nav::header<H: Host>(app: &App<H>) -> (String, Option<String>)` (location, update).
  - `App::tick(&mut self, now: Instant)`: loads the update notice once, polls a pending action (Task 8) and runs Setup steps.
  - `App::legacy_at_rest(&self) -> bool`.
- Home rows: `Status` "health, services, logs"; `Maintenance` "setup, settings files, database (until reworked)"; `Quit`.
- Maintenance (interim, sub-project 2 replaces it) rows: `Setup` "repair, update, components, ports, uninstall" → `open(Tab::Setup)`; `Settings files` "edit each service's configuration" → `open(Tab::Configuration)`; `Database` "status, migrate, maintenance" → `open(Tab::Database)`.

- [ ] **Step 1: Write the failing tests** (`nav_tests.rs`; add `#[cfg(test)] mod nav_tests;` to `tui/mod.rs`)

```rust
//! Navigation: Home, Esc, ?, q, and today's screens behind Maintenance.

use super::{
    app::{Key, Tab},
    nav::Screen,
    tests::{app, screen},
};

#[test]
fn a_set_up_host_opens_home_with_the_frame() {
    let app = app(false);
    assert_eq!(app.nav.screen, Screen::Home);
    let text = screen(&app, 80, 24);
    assert!(text.contains("██████╗"), "the logo:\n{text}");
    for want in ["Status", "Maintenance", "Quit", " q  Quit", "⭡⭣  Move"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    assert!(!text.contains("[Setup]"), "no tab bar any more");
}

#[test]
fn enter_opens_esc_goes_back_and_q_quits_only_from_home() {
    let mut app = app(false);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Status);
    app.key(Key::Char('q'));
    assert!(!app.quit, "q quits from Home only");
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
    app.key(Key::Char('q'));
    assert!(app.quit);
}

#[test]
fn question_mark_opens_help_and_esc_closes_it() {
    let mut app = app(false);
    app.key(Key::Char('?'));
    assert!(matches!(app.nav.screen, Screen::Help(_)));
    assert!(screen(&app, 80, 24).contains("Keys"));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Home);
}

#[test]
fn maintenance_reaches_todays_screens_and_esc_comes_back() {
    let mut app = app(false);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maintenance);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!((app.nav.screen.clone(), app.tab), (Screen::Legacy, Tab::Configuration));
    let text = screen(&app, 80, 24);
    assert!(text.starts_with("    limebox") || text.contains("Maintenance › Settings files"), "{text}");
    app.key(Key::Tab);
    assert_eq!(app.tab, Tab::Configuration, "Tab no longer switches screens");
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maintenance);
}

#[test]
fn esc_while_typing_in_a_legacy_screen_cancels_the_field_not_the_screen() {
    let mut app = app(false);
    app.open(Tab::Configuration);
    app.key(Key::Enter); // edit the first field
    assert!(app.config.editing.is_some());
    app.key(Key::Esc);
    assert!(app.config.editing.is_none(), "the field is cancelled");
    assert_eq!(app.nav.screen, Screen::Legacy, "still on the screen");
}

#[test]
fn a_fresh_host_opens_the_setup_form_and_esc_does_not_leave_it() {
    let mut app = super::setup_tests::fresh_app();
    assert_eq!((app.nav.screen.clone(), app.tab), (Screen::Legacy, Tab::Setup));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Legacy);
    app.key(Key::Char('q'));
    assert!(app.quit, "q still quits the install form");
}
```

`super::setup_tests::fresh_app()` is a new `pub(super)` helper in `setup_tests.rs`. It returns that file's existing not-set-up app; use the constructor `setup_tests.rs` already uses for a fresh host (its `app(false, …)`), with the arguments its other fresh-host tests pass.

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin nav_tests`
Expected: FAIL to compile (`nav` missing).

- [ ] **Step 3: Implement `nav.rs`**

```rust
//! Where the operator is (spec §3): a stack of screens. Enter opens, Esc
//! pops, ? opens Help, q quits from Home. Today's Setup, Configuration and
//! Database screens ("legacy") are reached from Maintenance and keep their
//! own keys; Tab and q are no longer theirs, and Esc leaves them only when
//! nothing is being typed or asked (sub-projects 2 and 3 replace them).

use platform_host::{Host, Unit};
use ratatui::Frame;

use super::{
    app::{App, Key, Tab},
    home, service, status,
    ui::{frame, list::Scroll, logo::Header},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Screen {
    Home,
    Status,
    Service(Unit),
    Log(Unit),
    Maintenance,
    Help(Box<Screen>),
    Legacy,
}

#[derive(Clone, Debug)]
pub struct Nav {
    pub screen: Screen,
    pub back: Vec<Screen>,
    pub row: usize,
    pub scroll: Scroll,
}

impl Nav {
    pub fn new(screen: Screen) -> Self {
        Self { screen, back: Vec::new(), row: 0, scroll: Scroll::default() }
    }
    pub fn go(&mut self, to: Screen) {
        let from = std::mem::replace(&mut self.screen, to);
        self.back.push(from);
        self.row = 0;
        self.scroll = Scroll::default();
    }
    /// Back one screen; false when there is nowhere to go.
    pub fn pop(&mut self) -> bool {
        let Some(previous) = self.back.pop() else { return false };
        self.screen = previous;
        self.row = 0;
        self.scroll = Scroll::default();
        true
    }
}

/// The location line's left part and the update notice.
pub fn header<H: Host>(app: &App<H>) -> (String, Option<String>) {
    let host = app.hostname.clone();
    let where_ = match &app.nav.screen {
        Screen::Home => String::new(),
        Screen::Status => " · Status".into(),
        Screen::Service(unit) | Screen::Log(unit) => format!(" · Status › {}", unit.label()),
        Screen::Maintenance => " · Maintenance".into(),
        Screen::Help(_) => " · Help".into(),
        Screen::Legacy => match app.tab {
            Tab::Setup if !app.setup_done() => " · Install".into(),
            Tab::Setup => " · Maintenance › Setup".into(),
            Tab::Configuration => " · Maintenance › Settings files".into(),
            _ => " · Maintenance › Database".into(),
        },
    };
    (format!("{host}{where_}"), app.update.clone())
}

pub fn render<H: Host>(frame: &mut Frame, app: &App<H>) {
    if frame::too_small(frame) {
        return;
    }
    let (location, update) = header(app);
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    let head = Header { location: &location, version: &version, update: update.as_deref() };
    match &app.nav.screen {
        Screen::Legacy => {
            let body = frame::legacy(frame, &app.theme, &head);
            super::legacy_view(frame, body, app);
        }
        Screen::Home => home::draw(frame, &head, app),
        Screen::Maintenance => home::draw_maintenance(frame, &head, app),
        Screen::Status => status::draw(frame, &head, app),
        Screen::Service(unit) => service::draw(frame, &head, app, *unit),
        Screen::Log(unit) => service::draw_log(frame, &head, app, *unit),
        Screen::Help(from) => home::draw_help(frame, &head, app, from),
    }
}

impl<H: Host> App<H> {
    /// The legacy screen has nothing typed, asked or running.
    pub fn legacy_at_rest(&self) -> bool {
        use super::setup::Phase;
        match self.tab {
            Tab::Setup => matches!(self.setup.phase, Phase::Status | Phase::Finished | Phase::Stopped(_)),
            Tab::Configuration => self.config.editing.is_none() && self.config.prompt.is_none(),
            Tab::Database => self.database.confirm.is_none(),
            Tab::Services | Tab::Health => true,
        }
    }

    pub(super) fn legacy_key(&mut self, key: Key) {
        match key {
            Key::Tab | Key::BackTab => {}
            Key::Char('q') if self.setup_done() || self.tab != Tab::Setup => {}
            Key::Esc if self.legacy_at_rest() && self.setup_done() => {
                if self.tab == Tab::Configuration && self.config_dirty() {
                    self.config.prompt = Some(super::configuration::Prompt::Discard(super::configuration::Then::Back));
                } else {
                    self.nav.pop();
                }
            }
            _ => self.legacy_dispatch(key),
        }
    }
}
```

In `configuration.rs`:
- add `Then::Back`, with `go(Then::Back) => { self.nav.pop(); }`;
- rename `dirty()` to `pub(super) fn config_dirty()` (update its callers).

In `app.rs`:
- rename `fn key` to `fn legacy_dispatch` (the old per-tab match);
- add the new `pub fn key`:

```rust
pub fn key(&mut self, key: Key) {
    self.outcome = None;
    if self.nav.screen == Screen::Legacy {
        return self.legacy_key(key);
    }
    if self.question.is_some() {
        return self.question_key(key); // Task 8
    }
    if self.prompt.is_some() {
        return self.prompt_key(key); // Task 8
    }
    match key {
        Key::Char('?') if !matches!(self.nav.screen, Screen::Help(_)) => {
            let from = Box::new(self.nav.screen.clone());
            self.nav.go(Screen::Help(from));
        }
        Key::Esc => {
            self.nav.pop();
        }
        Key::Char('q') if self.nav.screen == Screen::Home => self.quit_or_ask(),
        _ => match self.nav.screen.clone() {
            Screen::Home => self.home_key(key),
            Screen::Maintenance => self.maintenance_key(key),
            Screen::Status => self.status_key(key),
            Screen::Service(unit) => self.service_key(unit, key),
            Screen::Log(_) => self.log_key(key),
            Screen::Help(_) | Screen::Legacy => {}
        },
    }
}
```

`question_key`, `prompt_key`, `status_key`, `service_key` and `log_key` come in Tasks 7–8. For this task, add them as empty `fn …(&mut self, …) {}` stubs so it compiles. `quit_or_ask` for now is `self.quit = true;` (Task 8 adds the question while work runs).

`App::open(tab)` becomes:
- `Tab::Services | Tab::Health` → `self.nav.go(Screen::Status)` plus the old loading;
- every other tab → sets `self.tab = tab`, then `self.nav.go(Screen::Legacy)` (or replaces the screen when already Legacy), keeping the old loading code.

New `App` fields:
- `pub theme: Theme` (from `Theme::from_env()`; this replaces `color`; `setup_view` and the others read `app.theme.color` where they read `app.color`);
- `pub nav: Nav` (`Nav::new(if set_up { Screen::Home } else { Screen::Legacy })`);
- `pub hostname: String` (already read in `new`; keep it);
- `pub update: Option<String>`;
- `versions_loaded: bool`;
- `pub fn setup_done(&self) -> bool { self.setup.previous.is_some() || self.host.is_set_up() }`.

`App::tick(now)`:

```rust
pub fn tick(&mut self, now: std::time::Instant) {
    if !self.versions_loaded {
        self.versions_loaded = true;
        self.update = self.host.packages().ok().and_then(|packages| {
            packages
                .iter()
                .find(|p| p.name == "openvibes-admin")
                .and_then(|p| p.available.as_deref())
                .map(|v| v.split('-').next().unwrap_or(v).to_owned())
        });
    }
    self.poll(now); // Task 8; a no-op stub until then
}
```

`home.rs`:

```rust
//! Home, the interim Maintenance menu, and Help (spec §3, §2).

use platform_host::Host;
use ratatui::{Frame, text::{Line, Span}, widgets::Paragraph};

use super::{
    app::{App, Key, Tab},
    nav::Screen,
    ui::{bar::Bar, frame, list::{self, Row}, logo::Header},
};

pub const HOME: [(&str, &str); 3] = [
    ("Status", "health, services, logs"),
    ("Maintenance", "setup, settings files, database"),
    ("Quit", ""),
];
pub const MAINTENANCE: [(&str, &str); 3] = [
    ("Setup", "repair, update, components, ports, uninstall"),
    ("Settings files", "edit each service's configuration"),
    ("Database", "status, migrate, maintenance"),
];

fn rows(items: &[(&str, &str)]) -> Vec<Row> {
    items.iter().map(|(n, v)| Row::entry(n, v)).collect()
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let area = frame::draw(frame, &app.theme, head, None, &app.bar(Bar::home(&[("Enter", "Open")])));
    let mut lines = vec![app.status_line(), Line::raw("")];
    let mut scroll = app.nav.scroll;
    lines.extend(list::lines(&app.theme, &rows(&HOME), app.nav.row, &mut scroll, area.height.saturating_sub(2), 15));
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw_maintenance<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let area = frame::draw(frame, &app.theme, head, Some("Maintenance"), &app.bar(Bar::keys(&[("Enter", "Open")])));
    let mut scroll = app.nav.scroll;
    let lines = list::lines(&app.theme, &rows(&MAINTENANCE), app.nav.row, &mut scroll, area.height, 18);
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw_help<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, from: &Screen) {
    let bar = Bar::Keys { keys: Vec::new(), nav: false, home: false };
    let area = frame::draw(frame, &app.theme, head, Some("Keys"), &bar);
    let t = &app.theme;
    let key = |k: &str| Span::styled(format!(" {k} "), t.key());
    let pair = |lk: &str, ld: &str, rk: &str, rd: &str| {
        let mut spans = vec![Span::raw("    "), key(lk)];
        spans.push(Span::raw(format!("{}{ld:<24}   ", " ".repeat(8usize.saturating_sub(lk.chars().count() + 2)))));
        if !rk.is_empty() {
            spans.push(key(rk));
            spans.push(Span::raw(format!("{}{rd}", " ".repeat(6usize.saturating_sub(rk.chars().count() + 2)))));
        }
        Line::from(spans)
    };
    let mut lines = vec![
        pair(t.up_down(), "move · lists scroll", "Esc", "back, or cancel"), Line::raw(""),
        pair("Enter", "open, change, confirm", "?", "this help"), Line::raw(""),
        pair("Space", "select or deselect", "q", "quit, from Home"), Line::raw(""),
        pair(t.left_right(), "Yes or No in a question", "", ""), Line::raw(""),
    ];
    lines.push(Line::styled(format!("    Here: {}", here(from)), t.dim()));
    frame.render_widget(Paragraph::new(lines), area);
}

/// What the keys do on the screen Help was opened from.
fn here(from: &Screen) -> &'static str {
    match from {
        Screen::Home => "Enter opens the highlighted entry.",
        Screen::Status => "Enter opens a service, or does what a problem's line says.",
        Screen::Service(_) => "Enter does the highlighted action; Full log shows every line.",
        Screen::Log(_) => "⭡⭣ scroll the log.",
        Screen::Maintenance => "Enter opens the highlighted entry.",
        Screen::Help(_) | Screen::Legacy => "",
    }
}

impl<H: Host> App<H> {
    pub(super) fn move_row(&mut self, key: Key, count: usize) -> bool {
        match key {
            Key::Down | Key::Char('j') if self.nav.row + 1 < count => self.nav.row += 1,
            Key::Up | Key::Char('k') if self.nav.row > 0 => self.nav.row -= 1,
            Key::Down | Key::Up | Key::Char('j' | 'k') => {}
            _ => return false,
        }
        true
    }

    pub(super) fn home_key(&mut self, key: Key) {
        if self.move_row(key, HOME.len()) {
            return;
        }
        if key == Key::Enter {
            match self.nav.row {
                0 => self.open(Tab::Health),
                1 => self.nav.go(Screen::Maintenance),
                _ => self.quit_or_ask(),
            }
        }
    }

    pub(super) fn maintenance_key(&mut self, key: Key) {
        if self.move_row(key, MAINTENANCE.len()) {
            return;
        }
        if key == Key::Enter {
            self.open([Tab::Setup, Tab::Configuration, Tab::Database][self.nav.row]);
        }
    }
}
```

`App::status_line()` (one line: `● All N services running` green, or `▲ N problems` yellow; the Status model in Task 7 fills it. Until then return `Line::raw("")`) and `App::bar(default: Bar) -> Bar` (returns the default here; Task 8 replaces it with the question, the prompt or work when one is active) go in `app.rs`.

`tui/mod.rs`:
- `render` becomes `nav::render(frame, app)`;
- a new `pub(super) fn legacy_view(frame, area, app)` holds the old per-tab match (`Tab::Setup => setup_view::draw`, …, `Tab::Services | Tab::Health => {}`);
- remove `mod banner` and its tests;
- add `mod home; mod nav; mod service; mod status;`; the `service.rs` and `status.rs` stubs exist from this task with an empty `draw`, and Tasks 7–8 fill them;
- in the loop, call `app.tick(Instant::now())` after `key_then_tick`;
- the refresh condition becomes `matches!(app.nav.screen, Screen::Status | Screen::Service(_)) && app.question.is_none() && app.prompt.is_none()`.

`setup.rs` `form_key`: add `Key::Esc if self.setup.previous.is_some() => self.setup.phase = Phase::Status,` before the catch-all arm. On a set-up host, Esc on the change-components form returns to Setup's own status screen; one more Esc leaves to Maintenance.

- [ ] **Step 4: Run all admin tests**

Run: `cargo test -p openvibes-admin 2>&1 | tail -30`
Expected: the new `nav_tests` PASS. The legacy tests pass after the Tab-to-`open` replacements listed under Files. Tests that check the old Services tab (`renders_services_at_80x24`, `restart_asks_first`, `periodic_refresh_does_not_read_logs`, `not_installed_offers_nothing`, `not_an_operator_is_explained`, `logs_follow_the_selection_and_q_quits`, `enable_at_boot_asks_for_the_password`, `too_small_asks_for_more_room`) fail. **Mark them `#[ignore = "replaced in Task 7/8"]`**, and Tasks 7–8 delete them as their replacements land. `cargo clippy -p openvibes-admin --all-targets -- -D warnings` passes.

- [ ] **Step 5: Commit**

```bash
git add -A crates/openvibes-admin/src/tui
git commit -m "TUI: one menu (Home, Maintenance), Esc/?/q, today's screens behind it"
```

---

### Task 7: Status — Needs attention, Services, checks

**Files:**
- Create/fill: `crates/openvibes-admin/src/tui/status.rs`, `crates/openvibes-admin/src/tui/status_tests.rs`
- Modify: `crates/openvibes-admin/src/tui/app.rs` (`status_line`, `status_key`)
- Delete from `tests.rs`: `renders_services_at_80x24`, `not_installed_offers_nothing`, `too_small_asks_for_more_room` (replaced here and by `ui::frame`'s test)

**Interfaces:**
- Consumes: `database::checks`, `App::services`, `ui::list`.
- Produces:
  - `pub enum Item { Problem { text: String, fix: Option<Fix> }, Service(Unit) }`
  - `#[derive(Clone, Copy, Debug, Eq, PartialEq)] pub enum Fix { Start(Unit), Enable(Unit) }`
  - `pub fn items(services: &[ServiceStatus], checks: &[Check]) -> Vec<Item>`
  - `App::status_items(&self) -> Vec<Item>`
  - `status::draw`
- Behaviour: an installed unit that is `failed` or `inactive` (except `Unit::Llm`, which idles until used, and `Unit::Maintenance`, a timer whose service is inactive between runs) is a problem "■ NAME is stopped" with `Fix::Start`. An installed unit not enabled at boot is "▲ NAME does not start at boot" with `Fix::Enable`. Health problems come from `database::checks` called with an **empty** services slice (the unit lines are built here, not there), then `uncovered`, `signer_checks`, `audit_check` and `tune_check` as `load_health` does today; those have no fix. Services: installed units only, rows `name  state  ready  since`. The checks summary line is `● N checks ok` (dim). Enter: on a Service → `Screen::Service(unit)`; on a problem with a fix → Task 8's question (`Fix::Start`) or password prompt (`Fix::Enable`); on one without a fix → nothing (the bar shows no Enter).

- [ ] **Step 1: Write the failing tests** (`status_tests.rs`)

```rust
//! Status against the fake host (`tests::FakeHost`: ingest active and
//! ready, distribution not installed, vulns failed, llm inactive,
//! maintenance active).

use platform_host::Unit;

use super::{
    app::Key,
    nav::Screen,
    status::{Fix, Item, items},
    tests::{app, screen},
};

#[test]
fn a_stopped_service_is_a_problem_first_and_llm_idling_is_not() {
    let app = app(false);
    let items = app.status_items();
    assert!(matches!(&items[0], Item::Problem { text, fix: Some(Fix::Start(Unit::Vulns)) } if text.contains("vulns is stopped")), "{:?}", items[0]);
    assert!(!items.iter().any(|i| matches!(i, Item::Problem { text, .. } if text.contains("llm"))));
    assert!(items.iter().any(|i| matches!(i, Item::Service(Unit::Ingest))));
    assert!(!items.iter().any(|i| matches!(i, Item::Service(Unit::Distribution))), "not installed: not listed");
}

#[test]
fn status_renders_problems_then_services_with_the_frame() {
    let mut app = app(false);
    app.key(Key::Enter); // Home → Status
    assert_eq!(app.nav.screen, Screen::Status);
    let text = screen(&app, 80, 24);
    for want in ["━━ Status", "Needs attention", "vulns is stopped", "Services", "ingest", "running", "Start vulns"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn enter_on_a_service_opens_it() {
    let mut app = app(false);
    app.key(Key::Enter);
    while !matches!(app.status_items()[app.nav.row], Item::Service(Unit::Ingest)) {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Service(Unit::Ingest));
}

#[test]
fn items_without_services_still_list_health_problems() {
    let checks = vec![super::database::Check { problem: true, text: "disk 92% used".into() }];
    let items = items(&[], &checks);
    assert!(matches!(&items[0], Item::Problem { text, fix: None } if text.contains("disk 92%")));
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin status_tests`
Expected: FAIL (`items` missing).

- [ ] **Step 3: Implement `status.rs`**

```rust
//! Status (spec §4): what needs attention first, then the installed
//! services (name, state, ready, since; no notes), then a checks summary.
//! There is no boot switch: a unit not enabled at boot is a problem whose
//! Enter fixes it.

use platform_host::{Host, ServiceStatus, Unit};
use ratatui::{Frame, text::{Line, Span}, widgets::Paragraph};

use super::{
    app::App,
    database::Check,
    ui::{bar::Bar, frame, list::{self, Row}, logo::Header},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Fix {
    Start(Unit),
    Enable(Unit),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Item {
    Problem { text: String, fix: Option<Fix> },
    Service(Unit),
}

/// Idle by design while stopped: the model server starts on use, the
/// maintenance timer's service between runs.
fn idles(unit: Unit) -> bool {
    matches!(unit, Unit::Llm | Unit::Maintenance)
}

pub fn items(services: &[ServiceStatus], checks: &[Check]) -> Vec<Item> {
    let mut out = Vec::new();
    for s in services.iter().filter(|s| s.installed) {
        if !idles(s.unit) && matches!(s.active.as_str(), "failed" | "inactive") {
            out.push(Item::Problem { text: format!("{} is stopped", s.unit.label()), fix: Some(Fix::Start(s.unit)) });
        } else if !s.enabled {
            out.push(Item::Problem { text: format!("{} does not start at boot", s.unit.label()), fix: Some(Fix::Enable(s.unit)) });
        }
    }
    out.extend(checks.iter().filter(|c| c.problem).map(|c| Item::Problem { text: c.text.clone(), fix: None }));
    out.extend(services.iter().filter(|s| s.installed).map(|s| Item::Service(s.unit)));
    out
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let items = app.status_items();
    let enter = match items.get(app.nav.row) {
        Some(Item::Service(unit)) => vec![("Enter".to_owned(), format!("Open {}", unit.label()))],
        Some(Item::Problem { fix: Some(Fix::Start(unit)), .. }) => vec![("Enter".to_owned(), format!("Start {}", unit.label()))],
        Some(Item::Problem { fix: Some(Fix::Enable(unit)), .. }) => vec![("Enter".to_owned(), format!("Fix {}", unit.label()))],
        _ => Vec::new(),
    };
    let keys: Vec<(&str, &str)> = enter.iter().map(|(k, l)| (k.as_str(), l.as_str())).collect();
    let area = frame::draw(frame, &app.theme, head, Some("Status"), &app.bar(Bar::keys(&keys)));
    let t = &app.theme;
    let mut rows = Vec::new();
    let problems: Vec<&Item> = items.iter().filter(|i| matches!(i, Item::Problem { .. })).collect();
    if !problems.is_empty() {
        rows.push(Row::Heading { text: "Needs attention".into(), right: String::new() });
        for item in problems {
            let Item::Problem { text, fix } = item else { continue };
            let (mark, style) = if matches!(fix, Some(Fix::Start(_))) { ("■ ", t.red()) } else { ("▲ ", t.yellow()) };
            rows.push(Row::Entry { name: vec![Span::styled(mark, style), Span::raw(text.clone())], value: Vec::new() });
        }
    }
    let running = app.services.iter().filter(|s| s.installed && s.active == "active").count();
    let installed = app.services.iter().filter(|s| s.installed).count();
    rows.push(Row::Heading { text: "Services".into(), right: format!("{running} of {installed} running") });
    for s in app.services.iter().filter(|s| s.installed) {
        let dot = if s.active == "active" { Span::styled("● ", t.green()) } else { Span::styled("■ ", t.red()) };
        let ready = match s.ready { Some(true) => "ready", Some(false) => "not ready", None => "–" };
        rows.push(Row::Entry {
            name: vec![dot, Span::raw(s.unit.label().to_owned())],
            value: vec![Span::raw(format!("{:<9} {:<9} {}", s.active, ready, s.since.clone().unwrap_or_default()))],
        });
    }
    let mut scroll = app.nav.scroll;
    let mut lines = list::lines(t, &rows, app.nav.row, &mut scroll, area.height.saturating_sub(1), 18);
    let ok = app.database.health.iter().filter(|c| !c.problem).count();
    lines.push(Line::styled(format!("    ● {ok} checks ok"), t.dim()));
    frame.render_widget(Paragraph::new(lines), area);
}
```

In `app.rs`:

```rust
pub fn status_items(&self) -> Vec<super::status::Item> {
    super::status::items(&self.services, &self.database.health)
}

pub fn status_line(&self) -> ratatui::text::Line<'static> {
    use super::status::Item;
    use ratatui::text::{Line, Span};
    let problems = self.status_items().iter().filter(|i| matches!(i, Item::Problem { .. })).count();
    let installed = self.services.iter().filter(|s| s.installed).count();
    if problems == 0 {
        Line::from(vec![Span::raw("    "), Span::styled("● ", self.theme.green()), Span::raw(format!("All {installed} services running"))])
    } else {
        Line::from(vec![Span::raw("    "), Span::styled("▲ ", self.theme.yellow()), Span::raw(format!("{problems} things need attention · see Status"))])
    }
}

fn status_key(&mut self, key: Key) {
    let items = self.status_items();
    if self.move_row(key, items.len()) || key != Key::Enter {
        return;
    }
    match items.get(self.nav.row) {
        Some(super::status::Item::Service(unit)) => {
            let unit = *unit;
            self.nav.go(Screen::Service(unit));
            self.selected = self.services.iter().position(|s| s.unit == unit).unwrap_or(0);
            self.load_logs();
        }
        Some(super::status::Item::Problem { fix: Some(fix), .. }) => self.ask_fix(*fix), // Task 8
        _ => {}
    }
}
```

`load_health` must call `checks(&[], …)` (the empty services slice). Opening Status (`open(Tab::Health)`) runs `load_health`.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p openvibes-admin 2>&1 | tail -20`
Expected: `status_tests` PASS; the three old tests deleted; the rest as before.

- [ ] **Step 5: Commit**

```bash
git add -A crates/openvibes-admin/src/tui
git commit -m "TUI: Status (problems first, uniform service rows, no boot switch)"
```

---

### Task 8: Service screen, questions, password prompt, work to its result

**Files:**
- Create/fill: `crates/openvibes-admin/src/tui/service.rs`, `crates/openvibes-admin/src/tui/service_tests.rs`
- Modify: `crates/openvibes-admin/src/tui/app.rs` (`question`, `prompt`, `pending`, `outcome`, `question_key`, `prompt_key`, `ask_fix`, `quit_or_ask`, `poll`, `bar`)
- Delete from `tests.rs`: `restart_asks_first`, `periodic_refresh_does_not_read_logs`, `not_an_operator_is_explained`, `logs_follow_the_selection_and_q_quits`, `enable_at_boot_asks_for_the_password` (replaced here)

**Interfaces:**
- Produces:
  - `#[derive(Clone, Debug, Eq, PartialEq)] pub enum Question { Service(Unit, ServiceAction), Quit }` with `pub question: Option<(Question, bool)>` (the bool is the highlighted answer, `true` = Yes).
  - `pub prompt: Option<(Unit, PasswordPrompt)>` (enable at boot).
  - `pub struct Pending { pub unit: Unit, pub action: ServiceAction, pub since: Instant, pub polled: Instant }` with `pub pending: Option<Pending>` and `pub outcome: Option<(bool, String)>`.
  - `App::poll(&mut self, now: Instant)`.
  - `service::draw` and `service::draw_log`.
  - `pub const ACTION_TIMEOUT: Duration = Duration::from_secs(30)`.
- Entries on Service: running units get `Restart` and `Stop`; stopped ones get `Start`; all get `Full log`. Descriptions: Restart "agents reconnect within a minute" (`Unit::Ingest`); other units get "about a minute"; Stop "agents keep their findings until it runs" (ingest), others "until you start it"; Start "starts it now"; Full log "every line, newest at the bottom".
- Questions: `Restart ingest?` / `Stop ingest?` / `Start ingest?` with the description as detail.

- [ ] **Step 1: Write the failing tests** (`service_tests.rs`)

```rust
use std::time::{Duration, Instant};

use platform_host::{ServiceAction, Unit};

use super::{
    app::{Key, Question},
    nav::Screen,
    tests::{app, screen},
};

fn open_service(app: &mut super::app::App<super::tests::FakeHost>, unit: Unit) {
    app.open(super::app::Tab::Health);
    while !matches!(app.status_items()[app.nav.row], super::status::Item::Service(u) if u == unit) {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
}

#[test]
fn the_service_screen_says_which_service_and_offers_its_actions() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    let text = screen(&app, 80, 24);
    for want in ["━━ Service: ingest", "running · ready", "Restart", "Stop", "Full log", "Recent log", "first log line of ingest", "Enter  Restart ingest"] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

#[test]
fn restart_asks_with_buttons_and_enter_confirms() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    assert_eq!(app.question, Some((Question::Service(Unit::Ingest, ServiceAction::Restart), true)));
    let text = screen(&app, 80, 24);
    assert!(text.contains("Restart ingest?") && text.contains("Enter  Confirm") && !text.contains("Move"), "{text}");
    app.key(Key::Right); // No
    app.key(Key::Enter);
    assert!(app.question.is_none() && app.host.actions.borrow().is_empty(), "No does nothing");
    app.key(Key::Enter);
    app.key(Key::Enter); // Yes
    assert_eq!(*app.host.actions.borrow(), [(Unit::Ingest, ServiceAction::Restart)]);
    assert!(app.pending.is_some());
    assert!(screen(&app, 80, 24).contains("Restarting ingest…"));
}

#[test]
fn work_ends_in_one_result_line() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    let start = Instant::now();
    app.poll(start + Duration::from_secs(2));
    assert!(app.pending.is_none(), "ingest reports active and ready");
    let (ok, text) = app.outcome.clone().unwrap();
    assert!(ok && text.starts_with("ingest restarted and ready"), "{text}");
}

#[test]
fn a_unit_that_never_gets_ready_fails_after_the_timeout_with_its_last_log_line() {
    let mut app = app(false);
    open_service(&mut app, Unit::Vulns); // failed in the fake
    app.key(Key::Enter); // Start
    app.key(Key::Char('y'));
    let start = Instant::now();
    app.poll(start + Duration::from_secs(5));
    assert!(app.pending.is_some(), "still waiting");
    app.poll(start + super::app::ACTION_TIMEOUT + Duration::from_secs(1));
    let (ok, text) = app.outcome.clone().unwrap();
    assert!(!ok && text.contains("vulns did not start within 30 s") && text.contains("first log line of vulns"), "{text}");
}

#[test]
fn not_an_operator_is_explained_in_the_bar() {
    let mut app = app(true);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    let (ok, text) = app.outcome.clone().unwrap();
    assert!(!ok && text.contains("openvibes-operators"), "{text}");
}

#[test]
fn full_log_shows_the_log_and_esc_comes_back() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Log(Unit::Ingest));
    assert!(screen(&app, 80, 24).contains("first log line of ingest"));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Service(Unit::Ingest));
}
```

The at-boot fix needs the fake to report a unit as not enabled. In `tests.rs`, make `FakeHost`'s `actions` and `privileged_calls` fields `pub(super)`, and add `pub(super) disabled: RefCell<Vec<Unit>>` (initialised empty in `app()`). In `services()`, set `enabled: installed && !self.disabled.borrow().contains(&unit)`.

```rust
#[test]
fn fix_at_boot_asks_for_the_password_in_the_bar() {
    let mut app = app(false);
    app.host.disabled.borrow_mut().push(Unit::Ingest);
    app.open(super::app::Tab::Health);
    while !matches!(&app.status_items()[app.nav.row], super::status::Item::Problem { text, .. } if text.contains("ingest does not start at boot")) {
        app.key(Key::Down);
    }
    app.key(Key::Enter);
    let text = screen(&app, 80, 24);
    assert!(text.contains("Your password (sudo):") && text.contains("Enter  Enable"), "{text}");
    for c in "pw".chars() {
        app.key(Key::Char(c));
    }
    app.key(Key::Enter);
    assert_eq!(*app.host.privileged_calls.borrow(), [("unit-enable openvibes-ingest.service".to_owned(), "pw".to_owned())]);
    assert_eq!(app.outcome, Some((true, "ingest now starts at boot".into())));
}

#[test]
fn q_on_home_while_work_runs_asks_first() {
    let mut app = app(false);
    open_service(&mut app, Unit::Ingest);
    app.key(Key::Enter);
    app.key(Key::Char('y'));
    app.key(Key::Esc);
    app.key(Key::Esc); // Home
    app.key(Key::Char('q'));
    assert_eq!(app.question, Some((Question::Quit, true)));
    assert!(!app.quit);
    app.key(Key::Enter);
    assert!(app.quit);
}
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cargo test -p openvibes-admin service_tests`
Expected: FAIL to compile.

- [ ] **Step 3: Implement**

`app.rs` additions:

```rust
pub const ACTION_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Question {
    Service(Unit, ServiceAction),
    Quit,
}

pub struct Pending {
    pub unit: Unit,
    pub action: ServiceAction,
    pub since: std::time::Instant,
    pub polled: std::time::Instant,
}

// fields: pub question: Option<(Question, bool)>, pub prompt: Option<(Unit, PasswordPrompt)>,
//         pub pending: Option<Pending>, pub outcome: Option<(bool, String)>, tick_count: usize

pub fn bar(&self, default: Bar) -> Bar {
    if let Some((question, yes)) = &self.question {
        let (q, d) = match question {
            Question::Service(unit, action) => (
                format!("{} {}?", capitalised(*action), unit.label()),
                super::service::detail(*unit, *action).to_owned(),
            ),
            Question::Quit => ("Quit while it runs?".to_owned(), "it keeps running".to_owned()),
        };
        return Bar::Ask { question: q, detail: d, yes: *yes };
    }
    if let Some((_, prompt)) = &self.prompt {
        return Bar::Typing { label: "Your password (sudo)".into(), shown: prompt.masked(), done: "Enable".into() };
    }
    if let Some(p) = &self.pending {
        return Bar::Busy { text: format!("{} {}…", progressive(p.action), p.unit.label()), tick: self.tick_count };
    }
    if let Some((ok, text)) = &self.outcome {
        return Bar::Done { ok: *ok, text: text.clone() };
    }
    default
}

fn question_key(&mut self, key: Key) {
    let Some((question, yes)) = self.question.take() else { return };
    let answer = match key {
        Key::Left | Key::Right => {
            self.question = Some((question, !yes));
            return;
        }
        Key::Enter => yes,
        Key::Char('y') => true,
        Key::Char('n') | Key::Esc => false,
        _ => {
            self.question = Some((question, yes));
            return;
        }
    };
    if !answer {
        return;
    }
    match question {
        Question::Quit => self.quit = true,
        Question::Service(unit, action) => match self.host.service_action(unit, action) {
            Ok(()) => {
                let now = std::time::Instant::now();
                self.pending = Some(Pending { unit, action, since: now, polled: now });
            }
            Err(error) => self.outcome = Some((false, error.to_string())),
        },
    }
}

fn prompt_key(&mut self, key: Key) {
    let Some((unit, mut prompt)) = self.prompt.take() else { return };
    match prompt.key(key) {
        Typed::Pending => self.prompt = Some((unit, prompt)),
        Typed::Cancelled => {}
        Typed::Entered(secret) => {
            self.outcome = Some(match self.host.privileged(Privileged::UnitEnable(unit), &secret) {
                Ok(_) => (true, format!("{} now starts at boot", unit.label())),
                Err(error) => (false, error.to_string()),
            });
            self.refresh();
        }
    }
}

pub(super) fn ask_fix(&mut self, fix: super::status::Fix) {
    match fix {
        super::status::Fix::Start(unit) => self.question = Some((Question::Service(unit, ServiceAction::Start), true)),
        super::status::Fix::Enable(unit) => self.prompt = Some((unit, PasswordPrompt::default())),
    }
}

pub(super) fn quit_or_ask(&mut self) {
    if self.pending.is_some() {
        self.question = Some((Question::Quit, true));
    } else {
        self.quit = true;
    }
}

/// Polls a running action about once a second until its unit reaches the
/// state it was asked for, or the timeout passes.
pub fn poll(&mut self, now: std::time::Instant) {
    self.tick_count = self.tick_count.wrapping_add(1);
    let Some(p) = &self.pending else { return };
    if now.saturating_duration_since(p.polled) < std::time::Duration::from_secs(1) {
        return;
    }
    let (unit, action, since) = (p.unit, p.action, p.since);
    self.refresh();
    let status = self.services.iter().find(|s| s.unit == unit);
    let reached = status.is_some_and(|s| match action {
        ServiceAction::Stop => s.active != "active",
        _ => s.active == "active" && s.ready != Some(false),
    });
    let secs = now.saturating_duration_since(since).as_secs();
    if reached {
        self.pending = None;
        self.outcome = Some((true, format!("{} {} ({secs} s)", unit.label(), done_text(action))));
        self.load_logs();
    } else if now.saturating_duration_since(since) > ACTION_TIMEOUT {
        self.pending = None;
        let last = self.host.logs(unit, 1).ok().and_then(|l| l.last().cloned()).unwrap_or_default();
        let verb = match action { ServiceAction::Stop => "stop", _ => "start" };
        self.outcome = Some((false, format!("{} did not {verb} within {} s: {}", unit.label(), ACTION_TIMEOUT.as_secs(), super::service::readable(&last))));
    } else if let Some(p) = &mut self.pending {
        p.polled = now;
    }
}

fn capitalised(action: ServiceAction) -> &'static str {
    match action { ServiceAction::Start => "Start", ServiceAction::Stop => "Stop", ServiceAction::Restart => "Restart" }
}
fn progressive(action: ServiceAction) -> &'static str {
    match action { ServiceAction::Start => "Starting", ServiceAction::Stop => "Stopping", ServiceAction::Restart => "Restarting" }
}
fn done_text(action: ServiceAction) -> &'static str {
    match action { ServiceAction::Start => "started and ready", ServiceAction::Stop => "stopped", ServiceAction::Restart => "restarted and ready" }
}
```

`App::key` sets `self.outcome = None` first (Task 6). The result line therefore stays until the next key press.

In the Task 8 tests, `poll` is called directly with a chosen `now`. `work_ends_in_one_result_line` passes `start + 2 s`. Its pending `polled` was set at the real `Instant::now()` in `question_key`, which is earlier, so the one-second gate is passed.

`service.rs`:

```rust
//! Service: <name> (spec §4): which service, its state, its actions as
//! entries (the bar names what Enter does), and its latest log lines;
//! Full log shows every line.

use platform_host::{Host, ServiceAction, Unit};
use ratatui::{Frame, text::{Line, Span}, widgets::Paragraph};

use super::{
    app::{App, Key, Question},
    nav::Screen,
    ui::{bar::Bar, frame, list::{self, Row}, logo::Header},
};

pub use super::services_text::readable;

/// What an action means for this unit (entry description and question detail).
pub fn detail(unit: Unit, action: ServiceAction) -> &'static str {
    match (unit, action) {
        (Unit::Ingest, ServiceAction::Restart) => "agents reconnect within a minute",
        (Unit::Ingest, ServiceAction::Stop) => "agents keep their findings until it runs",
        (_, ServiceAction::Restart) => "about a minute",
        (_, ServiceAction::Stop) => "until you start it",
        (_, ServiceAction::Start) => "starts it now",
    }
}

enum Action {
    Do(ServiceAction),
    FullLog,
}

fn actions<H: Host>(app: &App<H>, unit: Unit) -> Vec<Action> {
    let active = app.services.iter().any(|s| s.unit == unit && s.active == "active");
    let mut out = if active {
        vec![Action::Do(ServiceAction::Restart), Action::Do(ServiceAction::Stop)]
    } else {
        vec![Action::Do(ServiceAction::Start)]
    };
    out.push(Action::FullLog);
    out
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, unit: Unit) {
    let acts = actions(app, unit);
    let label = |a: &Action| match a {
        Action::Do(ServiceAction::Restart) => ("Restart".to_owned(), detail(unit, ServiceAction::Restart).to_owned()),
        Action::Do(ServiceAction::Stop) => ("Stop".to_owned(), detail(unit, ServiceAction::Stop).to_owned()),
        Action::Do(ServiceAction::Start) => ("Start".to_owned(), detail(unit, ServiceAction::Start).to_owned()),
        Action::FullLog => ("Full log".to_owned(), "every line, newest at the bottom".to_owned()),
    };
    let enter = acts.get(app.nav.row).map(|a| {
        let (name, _) = label(a);
        if matches!(a, Action::FullLog) { name } else { format!("{name} {}", unit.label()) }
    });
    let keys: Vec<(&str, &str)> = enter.as_deref().map(|e| vec![("Enter", e)]).unwrap_or_default();
    let area = frame::draw(frame, &app.theme, head, Some(&format!("Service: {}", unit.label())), &app.bar(Bar::keys(&keys)));
    let t = &app.theme;
    let status = app.services.iter().find(|s| s.unit == unit);
    let state = status.map_or("unknown".to_owned(), |s| {
        let ready = match s.ready { Some(true) => " · ready", Some(false) => " · not ready", None => "" };
        format!("{}{ready}{}", s.active, s.since.as_ref().map(|x| format!(" · since {x}")).unwrap_or_default())
    });
    let dot = if status.is_some_and(|s| s.active == "active") { Span::styled("● ", t.green()) } else { Span::styled("■ ", t.red()) };
    let mut lines = vec![Line::from(vec![Span::raw("    "), dot, Span::raw(state)])];
    let rows: Vec<Row> = acts.iter().map(|a| { let (n, v) = label(a); Row::entry(&n, &v) }).collect();
    let mut scroll = app.nav.scroll;
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, u16::try_from(rows.len() * 2 + 1).unwrap_or(7), 18));
    lines.push(Line::styled("    Recent log", t.bold()));
    let room = usize::from(area.height).saturating_sub(lines.len());
    let tail = app.logs.len().saturating_sub(room);
    lines.extend(app.logs[tail..].iter().map(|l| Line::raw(format!("    {}", readable(l)))));
    frame.render_widget(Paragraph::new(lines), area);
}

pub fn draw_log<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, unit: Unit) {
    let area = frame::draw(frame, &app.theme, head, Some(&format!("Log: {}", unit.label())), &app.bar(Bar::keys(&[])));
    let room = usize::from(area.height).saturating_sub(2);
    let end = app.logs.len().saturating_sub(app.nav.row);
    let start = end.saturating_sub(room);
    let t = &app.theme;
    let mut lines = vec![if start > 0 { Line::styled(format!("    {} {start} more lines", t.up()), t.dim()) } else { Line::raw("") }];
    lines.extend(app.logs[start..end].iter().map(|l| Line::raw(format!("    {}", readable(l)))));
    if app.nav.row > 0 {
        lines.push(Line::styled(format!("    {} {} more lines", t.down(), app.nav.row), t.dim()));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    pub(super) fn service_key(&mut self, unit: Unit, key: Key) {
        let acts = actions(self, unit);
        if self.move_row(key, acts.len()) || key != Key::Enter {
            return;
        }
        match acts.get(self.nav.row) {
            Some(Action::Do(action)) => self.question = Some((Question::Service(unit, *action), true)),
            Some(Action::FullLog) => {
                self.logs = self.host.logs(unit, 500).unwrap_or_else(|e| vec![e.to_string()]);
                self.nav.go(Screen::Log(unit));
            }
            None => {}
        }
    }

    /// In the full log, ⭡ goes back in time (row counts lines from the end).
    pub(super) fn log_key(&mut self, key: Key) {
        match key {
            Key::Up | Key::Char('k') if self.nav.row + 1 < self.logs.len() => self.nav.row += 1,
            Key::Down | Key::Char('j') if self.nav.row > 0 => self.nav.row -= 1,
            _ => {}
        }
    }
}
```

Move `readable()` and `safe()` with their three tests from `services.rs` into a new `services_text.rs` (`pub fn readable`). Delete `services.rs` (its screen is replaced) and remove `mod services;` from `tui/mod.rs`. Add `mod services_text;`.

Going back from Log to Service with Esc reloads the short log: in `Nav::pop`'s caller in `App::key` (the `Key::Esc` arm), after `self.nav.pop()`, if the screen is now `Screen::Service(_)`, call `self.load_logs()`.

- [ ] **Step 4: Run all admin tests and clippy**

Run: `cargo test -p openvibes-admin 2>&1 | tail -20 && cargo clippy -p openvibes-admin --all-targets -- -D warnings`
Expected: PASS, with no ignored tests left. Delete every `#[ignore = "replaced in Task 7/8"]` test (their replacements are in `status_tests.rs` and `service_tests.rs`).

- [ ] **Step 5: Commit**

```bash
git add -A crates/openvibes-admin/src/tui
git commit -m "TUI: Service screen, Yes/No questions, password in the bar, work to its result"
```

---

### Task 9: Docs, gate, and a real-terminal check

**Files:**
- Modify: `docs/components/openvibes-admin.md` ("Administration TUI" section)

- [ ] **Step 1: Update the component page**

Replace the tab-by-tab description with:
- the frame (spec §2, one paragraph);
- Home → Status / Maintenance / Quit;
- Status (problems first, Enter acts; no boot switch);
- Service (Restart / Stop / Start / Full log, the question, the result line, the 30 s timeout with the last journal line);
- Help;
- `TERM=linux` arrows;
- `NO_COLOR`;
- the interim Maintenance menu reaching today's Setup, Settings files and Database screens (until sub-projects 2 and 3);
- for testing, the `TestBackend` tests in `nav_tests.rs`, `status_tests.rs` and `service_tests.rs`, and the `ui::*` unit tests.

Remove "Tab cycles screens" and the old key lists.

- [ ] **Step 2: The local gate**

Run the gate in `../testing.md` (build-console, fmt, names, clippy `--all-features`, doc, `cargo test --workspace --all-features`, audit).
Expected: green.

- [ ] **Step 3: A real terminal**

Run: `cargo run -q -p openvibes-admin` in an 80×24 terminal (and in one with `TERM=linux`, `NO_COLOR=1`). Walk Home → Status → a service → Restart (No) → Full log → Esc → Esc → Maintenance → Settings files → Esc → Esc → `?` → Esc → q. Compare with the approved mockups (`docs/specs/tui-rework/round3.py`, `service2.py`, `home3.py`, `general.py`): gaps, alignment, bar.
Expected: matches. Take a screenshot of Home and Status for the PR.

- [ ] **Step 4: Commit**

```bash
git add docs/components/openvibes-admin.md
git commit -m "Docs: the reworked TUI frame, Home, Status, Service"
```
