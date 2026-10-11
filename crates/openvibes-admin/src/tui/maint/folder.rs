//! The backup folder (approved.md 38): typed in place and checked as
//! typed, or picked with Tab in a browser of folders (⭡⭣, Enter opens,
//! Use this folder picks). Shared by Back up, Update and Uninstall.
//!
//! Typing only does the cheap checks (a full path to an existing
//! folder). The probe file and `df` can hang on a dead mount, so they run
//! on another thread once the typing pauses, and give up after a few
//! seconds.

use std::{
    path::{Path, PathBuf},
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant},
};

use platform_host::Host;
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    Page,
    backup::{cheap_check, check_folder},
};
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

/// How long the typing must rest before the slow check starts.
const PAUSE: Duration = Duration::from_millis(400);
/// How long the slow check may take: a dead mount never answers.
const PATIENCE: Duration = Duration::from_secs(5);

/// Starts the slow check of a folder on another thread (`run` sets it;
/// tests leave it out and `poll` checks at once on the TUI's own host).
pub type Checker = Box<dyn Fn(String) -> Receiver<Result<String, String>>>;

#[derive(Debug, Default)]
pub struct Folder {
    pub text: String,
    /// The check of `text`; `None` while the slow part is still to come.
    pub check: Option<Result<String, String>>,
    /// The folder before typing began: Esc puts it back.
    before: Option<String>,
    /// When the slow check starts.
    due: Option<Instant>,
    /// The slow check running on its thread, and since when.
    running: Option<(Receiver<Result<String, String>>, Instant)>,
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
    /// The slow check is still to come or running.
    pub fn pending(&self) -> bool {
        self.check.is_none() && (self.due.is_some() || self.running.is_some())
    }
    /// Takes `text`: the cheap check now, the slow one from `due` on.
    pub fn set(&mut self, text: String, due: Instant) {
        self.running = None;
        match cheap_check(&text) {
            Ok(_) => {
                self.check = None;
                self.due = Some(due);
            }
            Err(error) => {
                self.check = Some(Err(error));
                self.due = None;
            }
        }
        self.text = text;
    }
    pub fn key(&mut self, key: Key, now: Instant) -> Edited {
        let mut text = self.text.clone();
        match key {
            Key::Char(c) if text.chars().count() < 4096 => text.push(c),
            Key::Backspace => {
                text.pop();
            }
            Key::ClearLine => text.clear(),
            Key::Enter => {
                self.done();
                // Nothing more is coming: check now.
                self.due = self.due.map(|_| now);
                return Edited::Done;
            }
            Key::Esc => {
                if let Some(before) = self.before.take() {
                    self.set(before, now);
                }
                return Edited::Cancelled;
            }
            Key::Tab => return Edited::Browse,
            _ => return Edited::Typing,
        }
        self.set(text, now + PAUSE);
        Edited::Typing
    }

    /// Runs the slow check once due, and takes its answer or gives up.
    pub fn poll<H: Host>(&mut self, host: &H, checker: Option<&Checker>, now: Instant) {
        if let Some((rx, since)) = &self.running {
            let since = *since;
            match rx.try_recv() {
                Ok(result) => self.check = Some(result),
                Err(TryRecvError::Empty) if now.saturating_duration_since(since) < PATIENCE => {
                    return;
                }
                Err(TryRecvError::Empty) => {
                    self.check = Some(Err(format!(
                        "{} does not answer: is it mounted?",
                        self.text.trim()
                    )));
                }
                Err(TryRecvError::Disconnected) => {
                    self.check = Some(Err(format!("{} could not be checked", self.text.trim())));
                }
            }
            self.running = None;
            return;
        }
        if self.due.is_some_and(|due| due <= now) {
            self.due = None;
            let text = self.text.trim().to_owned();
            match checker {
                Some(start) => self.running = Some((start(text), now)),
                None => self.check = Some(check_folder(host, &text)),
            }
        }
    }
}

/// The folder's value on its row.
pub fn value(theme: &Theme, folder: &Folder) -> Vec<Span<'static>> {
    if folder.editing() {
        vec![Span::raw(format!("{}█", folder.text))]
    } else if folder.ok() || folder.pending() {
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
        None if folder.pending() => {
            Line::styled(format!("    Checking {}…", folder.text.trim()), theme.dim())
        }
        _ => Line::styled(
            "    A NAS mount, a backup disk: any folder this host can write.",
            theme.dim(),
        ),
    }
}

/// The bar while a folder is typed (flows.py).
pub fn bar() -> Bar {
    Bar::edit(
        "Folder",
        "type, or",
        &[("Tab", "to browse"), ("Enter", "Done")],
    )
}

#[derive(Debug)]
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
                Browse {
                    dir,
                    folders,
                    error: None,
                }
            }
            Err(error) => Browse {
                dir,
                folders: Vec::new(),
                error: Some(error.to_string()),
            },
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
        rows.extend(
            self.folders
                .iter()
                .map(|f| (format!("{f}/"), String::new())),
        );
        rows
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let Some(browse) = &app.maint.browse else {
        return;
    };
    let up = usize::from(browse.up().is_some());
    let enter = match app.nav.row {
        0 => "Use this folder",
        1 if up == 1 => "Up one folder",
        _ => "Open",
    };
    let area = frame::draw(
        frame,
        t,
        head,
        Some("Choose a folder"),
        &app.bar(Bar::keys(&[("Enter", enter)])),
    );
    let rows: Vec<Row> = browse
        .rows()
        .iter()
        .map(|(n, v)| Row::entry(n, v))
        .collect();
    let mut scroll = app.nav.scroll.get();
    let mut lines = list::lines(
        t,
        &rows,
        app.nav.row,
        &mut scroll,
        area.height.saturating_sub(1),
        22,
    );
    app.nav.scroll.set(scroll);
    lines.push(match &browse.error {
        Some(error) => Line::styled(
            format!("    {} cannot be read: {error}", browse.dir.display()),
            t.yellow(),
        ),
        None => Line::styled(
            "    Enter opens a folder; Use this folder picks the one shown.",
            t.dim(),
        ),
    });
    frame.render_widget(Paragraph::new(lines), area);
}

impl<H: Host> App<H> {
    /// Keys while the folder is typed; Tab opens the browser.
    pub(super) fn folder_key(&mut self, key: Key) {
        if let Edited::Browse = self.maint.folder.key(key, Instant::now()) {
            self.maint.browse = Some(Browse::at(&self.maint.folder.text));
            self.nav.go(Screen::Maint(Page::Folder));
        }
    }

    /// The slow part of the folder check, each tick.
    pub(in crate::tui) fn poll_folder(&mut self, now: Instant) {
        self.maint
            .folder
            .poll(&self.host, self.checker.as_ref(), now);
    }

    pub(super) fn browse_key(&mut self, key: Key) {
        let Some(browse) = &self.maint.browse else {
            return;
        };
        let count = browse.rows().len();
        let dir = browse.dir.clone();
        let up = browse.up().map(Path::to_path_buf);
        let row = self.nav.row;
        let target = match (row, &up) {
            (0, _) => None,
            (1, Some(parent)) => Some(parent.clone()),
            (_, _) => browse
                .folders
                .get(row - 1 - usize::from(up.is_some()))
                .map(|f| dir.join(f)),
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
                self.maint
                    .folder
                    .set(dir.display().to_string(), Instant::now());
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
