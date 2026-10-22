//! Backups (spec §6, §10.1, approved.md 37-38): a folder you choose and
//! the helper remembers; a new file name every time; Back up first off
//! by default, then your last choice.

use std::{path::Path, time::Instant};

use platform_host::{Host, StepState, UpdateStep};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{failure, folder, human};
use crate::{
    setup::backup::MEMORY,
    tui::{
        app::{App, Key},
        run::{Call, Kind, Run, Work},
        ui::{
            bar::Bar,
            frame,
            list::{self, Row},
            logo::Header,
        },
    },
};

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
            // The file is the helper's, but a folder is only used if it
            // reads as a full path without control characters.
            folder: table
                .get("folder")
                .and_then(toml::Value::as_str)
                .filter(|f| f.starts_with('/') && !f.chars().any(char::is_control))
                .map(str::to_owned),
            first: table
                .get("first")
                .and_then(toml::Value::as_bool)
                .unwrap_or(false),
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

/// A new backup file `base.dump`, or `base-2.dump`...: neither the dump
/// nor its `.roles.sql` may exist, so a stray roles file moves the name on.
pub fn free_backup(base: &str, exists: impl Fn(&str) -> bool) -> String {
    free_path(base, "dump", |p| {
        exists(p) || exists(&format!("{p}.roles.sql"))
    })
}

/// `base.ext`, or `base-2.ext`, `base-3.ext`... when taken.
pub fn free_path(base: &str, ext: &str, exists: impl Fn(&str) -> bool) -> String {
    std::iter::once(format!("{base}.{ext}"))
        .chain((2..).map(|n| format!("{base}-{n}.{ext}")))
        .find(|path| !exists(path))
        .unwrap_or_default()
}

/// What typing can afford (spec §2), on every key and without touching
/// the file system, which can hang on a dead mount: a full path. Returns
/// the path.
pub fn cheap_check(text: &str) -> Result<String, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("type a folder, or Tab to browse".into());
    }
    if !text.starts_with('/') {
        return Err("a full path, starting with /".into());
    }
    Ok(text.to_owned())
}

/// The whole check, which may block on a slow mount: the folder exists,
/// is a folder and is not reached through a symbolic link (the helper
/// refuses those), then a probe file and the free space. Never on the UI
/// thread.
pub fn check_folder<H: Host>(host: &H, text: &str) -> Result<String, String> {
    static PROBES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let text = cheap_check(text)?;
    let path = Path::new(&text);
    match std::fs::metadata(path) {
        Err(_) => return Err(format!("{text} does not exist")),
        Ok(meta) if !meta.is_dir() => return Err(format!("{text} is not a folder")),
        Ok(_) => {}
    }
    if let Ok(real) = std::fs::canonicalize(path)
        && real != path
    {
        return Err(format!(
            "{text} goes through a symbolic link: use {}",
            real.display()
        ));
    }
    // ponytail: a probe file made and removed at once (access(2) needs
    // unsafe). A root-squashed NFS folder passes here though the helper,
    // as root, cannot write there: its backup step then says so. The
    // counter keeps a stuck earlier probe from failing a later one.
    let probe = path.join(format!(
        ".openvibes-write-check-{}-{}",
        std::process::id(),
        PROBES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
        }
        Err(_) => return Err(format!("{text} is not writable for you")),
    }
    Ok(match host.free_space(&text) {
        Some(free) => format!("{text} exists and is writable · {free} free"),
        None => format!("{text} exists and is writable"),
    })
}

/// A new backup file in `folder`, named for the version whose data it holds.
pub fn next_file(folder: &str) -> String {
    let base = format!(
        "{}/{}",
        folder.trim().trim_end_matches('/'),
        file_stem(
            env!("CARGO_PKG_VERSION"),
            chrono::Local::now().naive_local()
        )
    );
    free_backup(&base, |p| Path::new(p).exists())
}

/// The size in the helper's "backup saved to X (N bytes) and …".
fn saved(detail: &str) -> Option<String> {
    let n: u64 = detail
        .split(" (")
        .nth(1)?
        .split(" bytes)")
        .next()?
        .parse()
        .ok()?;
    Some(human(n))
}

fn backup_run<H: Host>(app: &App<H>) -> Option<&Run> {
    app.run
        .as_ref()
        .filter(|r| matches!(r.work.kind, Kind::Backup { .. }))
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let run = backup_run(app);
    let folder = &app.maint.folder;
    let bar = match run {
        Some(r) if r.running() => Bar::Busy {
            text: "Backing up the database…".into(),
            tick: app.tick_count,
        },
        Some(r) if r.ok() => Bar::only(&[("Enter", "Done")]),
        Some(_) => Bar::act(&[("Enter", "Try again")]),
        None if folder.editing() => folder::bar(),
        None if app.nav.row == 0 => Bar::keys(&[("Enter", "Choose a folder")]),
        None => Bar::keys(&[("Enter", "Back up now")]),
    };
    let area = frame::draw(frame, t, head, Some("Back up"), &app.bar(bar));
    let mut lines = vec![
        Line::raw(""),
        Line::styled(
            "    The database: findings, alarms, cases, users, settings. Certificates",
            t.dim(),
        ),
        Line::styled(
            "    and keys are not in it: they stay in /etc/openvibes/pki.",
            t.dim(),
        ),
    ];
    let rows = vec![
        Row::Entry {
            name: vec![Span::raw("Save in folder")],
            value: folder::value(t, folder),
        },
        Row::entry("Back up now", "a new file each time"),
    ];
    let mut scroll = app.nav.scroll.get();
    lines.extend(list::lines(t, &rows, app.nav.row, &mut scroll, 5, 14));
    app.nav.scroll.set(scroll);
    match run {
        Some(r) if r.ok() => {
            let Kind::Backup { file } = &r.work.kind else {
                return;
            };
            let size = r.states[0]
                .as_ref()
                .and_then(|s| saved(s.detail()))
                .unwrap_or_default();
            // The size follows on a line of its own when the path leaves no room.
            let fits = file.chars().count() + size.chars().count() + 16 <= 80;
            let mut saved = vec![
                Span::raw("    "),
                Span::styled("✓", t.green()),
                Span::raw(" Saved "),
                Span::styled(file.clone(), t.bold()),
            ];
            if fits {
                saved.push(Span::raw(format!(" ({size})")));
            }
            lines.push(Line::from(saved));
            if !fits {
                lines.push(Line::styled(format!("    {size}"), t.dim()));
            }
            lines.push(Line::styled(
                "    Copy it off this host: a backup on the same disk does not survive the disk.",
                t.dim(),
            ));
        }
        Some(r) if !r.running() => {
            let why = r.states[0].as_ref().map_or("", StepState::detail);
            lines.extend(failure(
                t,
                why,
                "Nothing was changed: the services keep running.",
            ));
        }
        Some(_) => {}
        None if app.nav.row == 0 => lines.push(folder::help(t, folder)),
        None if folder.file.is_some() => lines.push(Line::styled(
            format!("    Writes {}.", folder.file.as_deref().unwrap_or_default()),
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
            self.maint.folder.set(text, Instant::now());
        }
    }

    /// A new file in the chosen folder (looks at the file system: once,
    /// on the key that starts the backup, never per frame).
    pub(in crate::tui) fn backup_file(&self) -> String {
        next_file(&self.maint.folder.text)
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
        if self.move_row(&key, 2) || key != Key::Enter {
            return;
        }
        if self.nav.row == 0 {
            return self.maint.folder.edit();
        }
        if !self.maint.folder.ok() {
            let why = if self.maint.folder.pending() {
                "Wait: the folder is still being checked"
            } else {
                "Choose a folder first"
            };
            self.outcome = Some((false, why.into()));
            self.nav.row = 0;
            return;
        }
        let file = self.backup_file();
        let call = Call::Update(UpdateStep::Backup, vec!["--backup".into(), file.clone()]);
        self.begin(Work::new(Kind::Backup { file }, vec![call]), 0);
    }
}

#[cfg(test)]
mod tests {
    use super::{Memory, check_folder, file_stem, free_backup, free_path};
    use crate::tui::tests::app;

    #[test]
    fn names_carry_the_version_date_and_time() {
        let at = chrono::NaiveDate::from_ymd_opt(2026, 10, 10)
            .unwrap()
            .and_hms_opt(20, 41, 7)
            .unwrap();
        assert_eq!(file_stem("0.2.9", at), "openvibes-0.2.9-2026-10-10-2041");
    }

    #[test]
    fn a_second_backup_in_the_same_minute_gets_its_own_name() {
        let taken = ["/b/x.dump", "/b/x-2.dump"];
        assert_eq!(
            free_path("/b/x", "dump", |p| taken.contains(&p)),
            "/b/x-3.dump"
        );
        assert_eq!(free_path("/b/x", "dump", |_| false), "/b/x.dump");
    }

    #[test]
    fn the_memory_is_empty_until_the_helper_writes_it() {
        assert_eq!(Memory::parse(""), Memory::default());
        assert_eq!(
            Memory::parse("folder = \"/mnt/nas/openvibes\"\nfirst = true\n"),
            Memory {
                folder: Some("/mnt/nas/openvibes".into()),
                first: true
            }
        );
        assert_eq!(
            Memory::load(std::path::Path::new("/nonexistent")),
            Memory::default()
        );
    }

    #[test]
    fn a_stray_roles_file_moves_the_name_on() {
        let dir = std::env::temp_dir().join(format!("ov-names-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let base = format!("{}/x", dir.display());
        let taken = |p: &str| std::path::Path::new(p).exists();
        assert_eq!(free_backup(&base, taken), format!("{base}.dump"));
        std::fs::write(format!("{base}.dump.roles.sql"), "x").unwrap();
        assert_eq!(free_backup(&base, taken), format!("{base}-2.dump"));
        std::fs::write(format!("{base}-2.dump"), "x").unwrap();
        assert_eq!(free_backup(&base, taken), format!("{base}-3.dump"));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_remembered_folder_must_be_a_full_path_without_control_characters() {
        for bad in [
            "folder = \"backups\"\n",
            "folder = \"\"\n",
            "folder = \"/mnt/a\\nb\"\n",
            "folder = \"/mnt/\\u001b[31m\"\n",
            "folder = 7\n",
        ] {
            assert_eq!(Memory::parse(bad).folder, None, "{bad}");
        }
        assert_eq!(
            Memory::parse("folder = \"/mnt/my backups\"\n").folder,
            Some("/mnt/my backups".into())
        );
    }

    #[test]
    fn the_folder_is_checked_as_typed() {
        let app = app(false);
        let dir = std::env::temp_dir().join(format!("ov-folder-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("a-file");
        std::fs::write(&file, "x").unwrap();
        let shown = dir.display().to_string();
        assert_eq!(
            check_folder(&app.host, ""),
            Err("type a folder, or Tab to browse".into())
        );
        assert!(super::cheap_check("/no/such/folder").is_ok(), "text only");
        assert_eq!(
            check_folder(&app.host, "backups"),
            Err("a full path, starting with /".into())
        );
        assert!(
            check_folder(&app.host, &format!("{shown}/nope"))
                .unwrap_err()
                .ends_with("does not exist")
        );
        assert!(
            check_folder(&app.host, &file.display().to_string())
                .unwrap_err()
                .ends_with("is not a folder")
        );
        std::os::unix::fs::symlink(&dir, dir.with_extension("link")).unwrap();
        let error =
            check_folder(&app.host, &dir.with_extension("link").display().to_string()).unwrap_err();
        assert!(
            error.contains("symbolic link") && error.contains(&shown),
            "{error}"
        );
        std::fs::remove_file(dir.with_extension("link")).unwrap();
        assert_eq!(
            check_folder(&app.host, &format!("{shown}/")),
            Ok(format!("{shown}/ exists and is writable"))
        );
        assert_eq!(
            check_folder(&app.host, &shown),
            Ok(format!("{shown} exists and is writable"))
        );
        assert!(
            std::fs::read_dir(&dir).unwrap().count() == 1,
            "the probe is gone"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
