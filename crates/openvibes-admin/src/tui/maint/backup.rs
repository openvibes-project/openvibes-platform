//! Backups (spec §6, §10.1, approved.md 37-38): a folder you choose and
//! the helper remembers; a new file name every time; Back up first off
//! by default, then your last choice.

use std::path::Path;

use platform_host::Host;

use crate::setup::backup::MEMORY;

/// What the helper remembered (`/etc/openvibes/backup.toml`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[allow(dead_code, reason = "first used in Task 6 of the 2a plan")]
pub struct Memory {
    pub folder: Option<String>,
    pub first: bool,
}

#[allow(dead_code, reason = "first used in Task 6 of the 2a plan")]
impl Memory {
    pub fn parse(text: &str) -> Memory {
        let table: toml::Table = text.parse().unwrap_or_default();
        Memory {
            folder: table
                .get("folder")
                .and_then(toml::Value::as_str)
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

/// `base.ext`, or `base-2.ext`, `base-3.ext`... when taken.
pub fn free_path(base: &str, ext: &str, exists: impl Fn(&str) -> bool) -> String {
    std::iter::once(format!("{base}.{ext}"))
        .chain((2..).map(|n| format!("{base}-{n}.{ext}")))
        .find(|path| !exists(path))
        .unwrap_or_default()
}

/// The folder as typed (spec §2): a full path to a folder you can write
/// to, with its free space; or what is wrong.
#[allow(dead_code, reason = "first used in Task 6 of the 2a plan")]
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
    Ok(match host.free_space(text) {
        Some(free) => format!("{text} exists and is writable · {free} free"),
        None => format!("{text} exists and is writable"),
    })
}

#[cfg(test)]
mod tests {
    use super::{Memory, check_folder, file_stem, free_path};
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
