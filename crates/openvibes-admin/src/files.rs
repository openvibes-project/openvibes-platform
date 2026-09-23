//! File handling for key and certificate material.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::Path,
};

/// Largest PEM input read.
const MAX_PEM_BYTES: u64 = 1024 * 1024;

/// Reads a PEM file of at most 1 MiB.
pub fn read_pem(path: &Path) -> Result<String, String> {
    let mut text = String::new();
    let read =
        File::open(path).and_then(|file| file.take(MAX_PEM_BYTES + 1).read_to_string(&mut text));
    match read {
        Ok(length) if length as u64 <= MAX_PEM_BYTES => Ok(text),
        Ok(_) => Err("input file exceeds 1 MiB".into()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err("input file not found".into()),
        Err(_) => Err("cannot read input file".into()),
    }
}

/// Creates `path` with `mode`, refusing to replace anything already there
/// (including a link). Private keys use `0o600`, certificates `0o644`.
pub fn write_new(path: &Path, contents: &str, mode: u32) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| "cannot create output directory".to_owned())?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, mode);
    #[cfg(not(unix))]
    let _ = mode;
    let mut file = options.open(path).map_err(|error| match error.kind() {
        io::ErrorKind::AlreadyExists => {
            format!("{} already exists; not overwritten", path.display())
        }
        _ => "cannot create output file".to_owned(),
    })?;
    file.write_all(contents.as_bytes())
        .and_then(|()| file.sync_all())
        .map_err(|_| "cannot write output file".to_owned())
}
