//! `/etc/openvibes/NAME.toml` as the root helper reads and replaces it
//! (admin TUI spec §3): only regular files, checked by the service's type,
//! replaced atomically with the original owner, group and mode, the old
//! file kept as `NAME.toml.bak`.

use std::{
    fs::{self, Metadata, OpenOptions, Permissions},
    io::{self, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

use platform_host::Service;

use crate::configs::{self, MAX_BYTES};

fn existing(path: &Path) -> Result<Metadata, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| match error.kind() {
        io::ErrorKind::NotFound => format!("{}: not installed (no such file)", path.display()),
        _ => format!("{}: {error}", path.display()),
    })?;
    if metadata.is_file() {
        Ok(metadata)
    } else {
        Err(format!("{}: not a regular file", path.display()))
    }
}

/// The file's text.
pub fn read(dir: &Path, service: Service) -> Result<String, String> {
    let path = dir.join(service.file_name());
    if existing(&path)?.len() > MAX_BYTES as u64 {
        return Err(format!("{}: larger than 64 KiB", path.display()));
    }
    fs::read_to_string(&path).map_err(|error| format!("{}: {error}", path.display()))
}

/// Replaces the file with `text` once the service's type accepts it.
pub fn replace(dir: &Path, service: Service, text: &str) -> Result<(), String> {
    let name = service.file_name();
    let path = dir.join(name);
    let metadata = existing(&path)?;
    configs::validate(service, text)?;
    let temp = dir.join(format!(".{name}.new"));
    // Left by an interrupted save; it is ours to replace.
    let _ = fs::remove_file(&temp);
    let result = write_temp(&temp, text, &metadata).and_then(|()| {
        fs::copy(&path, dir.join(format!("{name}.bak")))?;
        fs::rename(&temp, &path)?;
        fs::File::open(dir)?.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result.map_err(|error| format!("{}: {error}", path.display()))
}

/// Temp file, then owner and group, then mode (chown clears set-id bits).
fn write_temp(temp: &Path, text: &str, like: &Metadata) -> io::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(temp)?;
    file.write_all(text.as_bytes())?;
    std::os::unix::fs::fchown(&file, Some(like.uid()), Some(like.gid()))?;
    file.set_permissions(Permissions::from_mode(like.mode() & 0o7777))?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
    };

    use platform_host::Service;

    use super::{read, replace};

    const OLD: &str = "# kept\ndatabase_url = \"postgresql:///old\"\n";
    const NEW: &str = "# kept\ndatabase_url = \"postgresql:///new\"\n";

    fn dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ov-config-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn admin_file(dir: &Path) -> PathBuf {
        let path = dir.join("admin.toml");
        fs::write(&path, OLD).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        path
    }

    #[test]
    fn replaces_atomically_keeping_owner_mode_and_backup() {
        let dir = dir("replace");
        let path = admin_file(&dir);
        let before = fs::metadata(&path).unwrap();
        replace(&dir, Service::Admin, NEW).unwrap();
        let after = fs::metadata(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), NEW);
        assert_eq!(after.mode() & 0o7777, 0o640);
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(fs::read_to_string(dir.join("admin.toml.bak")).unwrap(), OLD);
        assert!(!dir.join(".admin.toml.new").exists());
        assert_eq!(read(&dir, Service::Admin).unwrap(), NEW);
    }

    #[test]
    fn an_invalid_file_is_refused_and_the_old_one_kept() {
        let dir = dir("invalid");
        let path = admin_file(&dir);
        assert!(replace(&dir, Service::Admin, "database_url = 1\n").is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), OLD);
        assert!(!dir.join("admin.toml.bak").exists());
    }

    #[test]
    fn a_symlink_or_missing_file_is_refused() {
        let dir = dir("links");
        assert!(
            read(&dir, Service::Admin)
                .unwrap_err()
                .contains("not installed")
        );
        assert!(
            replace(&dir, Service::Admin, NEW)
                .unwrap_err()
                .contains("not installed")
        );
        let target = dir.join("elsewhere.toml");
        fs::write(&target, OLD).unwrap();
        std::os::unix::fs::symlink(&target, dir.join("admin.toml")).unwrap();
        assert!(
            read(&dir, Service::Admin)
                .unwrap_err()
                .contains("not a regular file")
        );
        assert!(
            replace(&dir, Service::Admin, NEW)
                .unwrap_err()
                .contains("not a regular file")
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), OLD);
    }

    #[test]
    fn a_leftover_temp_file_does_not_block_a_save() {
        let dir = dir("leftover");
        admin_file(&dir);
        fs::write(dir.join(".admin.toml.new"), "junk").unwrap();
        replace(&dir, Service::Admin, NEW).unwrap();
        assert_eq!(read(&dir, Service::Admin).unwrap(), NEW);
    }
}
