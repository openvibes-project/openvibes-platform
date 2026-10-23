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
    backup::{cheap_check, check_folder, next_file},
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
    /// The file a backup would write, worked out once when the check succeeds.
    pub file: Option<String>,
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
        self.file = None;
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

    fn finish(&mut self, result: Result<String, String>) {
        self.file = result.is_ok().then(|| next_file(&self.text));
        self.check = Some(result);
    }

    /// Runs the slow check once due, and takes its answer or gives up.
    pub fn poll<H: Host>(&mut self, host: &H, checker: Option<&Checker>, now: Instant) {
        if let Some((rx, since)) = &self.running {
            let since = *since;
            match rx.try_recv() {
                Ok(result) => self.finish(result),
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
                None => {
                    let result = check_folder(host, &text);
                    self.finish(result);
                }
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
    /// The files too, to pick one ("From a file on this host").
    pub show_files: bool,
    pub files: Vec<String>,
    pub error: Option<String>,
    /// Why the file picked was refused, a sentence of its own.
    pub refused: Option<String>,
}

impl Browse {
    // ponytail: `is_dir` and `read_dir` run on the UI thread, once per
    // open: a dead mount can still freeze the key that opens it. Upgrade:
    // list on a thread like the folder check.
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
        Browse::list(dir, false)
    }
    /// As `open`, with the files: Enter on one picks it.
    pub fn open_files(dir: PathBuf) -> Browse {
        Browse::list(dir, true)
    }
    /// `open_files` at `path`, else its nearest parent that exists, else /.
    pub fn files_at(path: &str) -> Browse {
        let at = Browse::at(path);
        Browse::open_files(at.dir)
    }
    fn list(dir: PathBuf, show_files: bool) -> Browse {
        let (mut folders, mut files) = (Vec::new(), Vec::new());
        let error = match std::fs::read_dir(&dir) {
            Ok(entries) => {
                for entry in entries.filter_map(Result::ok) {
                    let Ok(name) = entry.file_name().into_string() else {
                        continue;
                    };
                    // A symbolic link is not offered: the helper refuses them.
                    match entry.file_type() {
                        _ if name.starts_with('.') => {}
                        Ok(t) if t.is_dir() => folders.push(name),
                        Ok(t) if t.is_file() && show_files => files.push(name),
                        _ => {}
                    }
                }
                None
            }
            Err(error) => Some(error.to_string()),
        };
        folders.sort();
        files.sort();
        Browse {
            dir,
            folders,
            show_files,
            files,
            error,
            refused: None,
        }
    }
    fn up(&self) -> Option<&Path> {
        self.dir.parent()
    }
    /// Use this folder (not when picking a file), `..` (unless at /), the
    /// folders, then the files.
    pub fn rows(&self) -> Vec<(String, String)> {
        let mut rows = Vec::new();
        if !self.show_files {
            rows.push(("Use this folder".to_owned(), self.dir.display().to_string()));
        }
        if self.up().is_some() {
            rows.push(("..".to_owned(), "up one folder".to_owned()));
        }
        rows.extend(
            self.folders
                .iter()
                .map(|f| (format!("{f}/"), String::new())),
        );
        rows.extend(self.files.iter().map(|f| (f.clone(), String::new())));
        rows
    }

    /// What Enter on a row of a file browser opens: a folder (true) or a
    /// file (false).
    pub fn target(&self, row: usize) -> Option<(PathBuf, bool)> {
        let up = self.up().map(Path::to_path_buf);
        let row = row.checked_sub(usize::from(!self.show_files))?;
        match (row, up) {
            (0, Some(parent)) => Some((parent, true)),
            (row, up) => {
                let i = row - usize::from(up.is_some());
                match self.folders.get(i) {
                    Some(f) => Some((self.dir.join(f), true)),
                    None => self
                        .files
                        .get(i - self.folders.len())
                        .map(|f| (self.dir.join(f), false)),
                }
            }
        }
    }
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    if let Some(browse) = &app.maint.browse {
        draw_browse(frame, head, app, browse);
    }
}

/// The browser of folders, or of files to pick one.
pub fn draw_browse<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, browse: &Browse) {
    let t = &app.theme;
    let enter = match (browse.show_files, browse.target(app.nav.row)) {
        (false, None) => "Use this folder",
        (_, Some((_, false))) => "Use this file",
        (_, Some((dir, true))) if browse.up() == Some(dir.as_path()) => "Up one folder",
        _ => "Open",
    };
    let title = if browse.show_files {
        "Choose a file"
    } else {
        "Choose a folder"
    };
    let area = frame::draw(
        frame,
        t,
        head,
        Some(title),
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
    lines.push(match (&browse.refused, &browse.error) {
        (Some(why), _) => Line::styled(format!("    {why}"), t.red()),
        (None, Some(error)) => Line::styled(
            format!("    {} cannot be read: {error}", browse.dir.display()),
            t.yellow(),
        ),
        _ if browse.show_files => {
            Line::styled("    Enter opens a folder or picks a file.", t.dim())
        }
        _ => Line::styled(
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
        if self.move_row(&key, count) {
            return;
        }
        match key {
            Key::Esc => {
                self.maint.browse = None;
                self.back();
            }
            // The bar promises ? (Help); Esc there returns to the browser.
            Key::Char('?') => {
                let from = Box::new(self.nav.screen.clone());
                self.nav.go(Screen::Help(from));
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
