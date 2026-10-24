//! What the install's Certificates step and Maintenance › Certificates ›
//! Replace both need around the CA: the helper's refusal as a sentence,
//! a file picked in the file browser, and reading it (at most `MAX`).
//! Your own CA's request, paste box and two ways to add a certificate are
//! the install's screens (`install/certs.rs`, `install/paste.rs`), which
//! Replace opens as they are.

use std::{cell::Cell, io::Read, path::PathBuf};

use super::{app::Key, maint::folder::Browse, ui::list::Scroll};

/// The most a paste or a file gives: a certificate or a key is ~1 KiB.
pub const MAX: usize = 64 * 1024;

/// What the helper's failure says, without its prefixes.
pub fn sentence(why: &str) -> String {
    match why.rsplit_once("openvibes-admin helper: ") {
        Some((_, said)) => said.trim().to_owned(),
        None => why
            .strip_prefix("failed: ")
            .unwrap_or(why)
            .trim()
            .to_owned(),
    }
}

/// What a key in the file browser did.
pub enum Picked {
    Nothing,
    /// Esc: the browser is closed.
    Closed,
    /// Enter on a file.
    File(PathBuf),
}

/// The file browser's keys: ⭡⭣ move, Enter opens a folder or picks a
/// file, Esc closes it.
pub fn pick(
    browse: &mut Option<Browse>,
    row: &mut usize,
    scroll: &Cell<Scroll>,
    key: Key,
) -> Picked {
    let Some(open) = browse.as_mut() else {
        return Picked::Nothing;
    };
    match key {
        Key::Down | Key::Char('j') if *row + 1 < open.rows().len() => *row += 1,
        Key::Up | Key::Char('k') => *row = row.saturating_sub(1),
        Key::Esc => {
            *browse = None;
            return Picked::Closed;
        }
        Key::Enter => match open.target(*row) {
            Some((path, true)) => {
                *browse = Some(Browse::open_files(path));
                *row = 0;
                scroll.set(Scroll::default());
            }
            Some((path, false)) => {
                // What the last pick said is for that file only.
                open.refused = None;
                open.error = None;
                return Picked::File(path);
            }
            None => {}
        },
        _ => {}
    }
    Picked::Nothing
}

/// The file's text, at most `MAX` bytes of it.
pub fn read(path: &std::path::Path) -> std::io::Result<String> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(MAX as u64)
        .read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
