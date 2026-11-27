//! The appliance's update file (#674, Decision #664): `update-check` asks
//! GitHub for the latest release, `update-fetch VERSION` downloads its
//! `openvibes-appliance-update-VERSION.tar`, and `update-use VERSION`
//! unpacks it, checks it against the keys the appliance was installed with
//! (gpgv: a keyring made from them alone, so only their signature counts),
//! every file against `SHA256SUMS` and nothing else in it, then makes its
//! repository the appliance's package source. Update then upgrades from it.
//! The file, not GitHub, is trusted: the same check serves a file dropped
//! over SFTP (#568).

use std::{
    collections::BTreeSet,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use platform_host::runner::{
    Program::{Curl, Df, Gpg, Gpgv, Tar},
    Runner,
};
use sha2::{Digest, Sha256};

/// Where update files are downloaded and unpacked.
pub const DIR: &str = "var/lib/openvibes/updates";
/// The appliance's package source (#558).
pub const REPO: &str = "var/lib/openvibes-appliance/repo";
const API: &str =
    "https://api.github.com/repos/openvibes-project/openvibes-platform/releases/latest";
const DOWNLOADS: &str = "https://github.com/openvibes-project/openvibes-platform/releases/download";
/// The keys installed with the appliance that may sign an update file.
const KEYS: [&str; 2] = [
    "etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes-appliance",
    "etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes-appliance-packages",
];
const TREE: &str = "openvibes-appliance-update";

/// A release version as tags carry it: digits first, then version
/// characters; never a path.
pub fn check_version(version: &str) -> Result<(), String> {
    let ok = version.len() <= 40
        && version.starts_with(|c: char| c.is_ascii_digit())
        && version
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".+~_-".contains(c));
    if ok {
        Ok(())
    } else {
        Err(format!("{version} is not a release version"))
    }
}

pub fn file_name(version: &str) -> String {
    format!("{TREE}-{version}.tar")
}

/// The latest release with an update file, from GitHub's answer.
#[derive(Debug, Eq, PartialEq)]
pub struct Release {
    pub version: String,
    /// `YYYY-MM-DD`.
    pub published: String,
    pub size: u64,
    /// The release notes' first line, as Update's "New:" line.
    pub new: String,
}

pub fn latest(json: &str) -> Result<Option<Release>, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|error| format!("GitHub's answer: {error}"))?;
    let tag = value["tag_name"].as_str().unwrap_or_default();
    let version = tag.strip_prefix('v').unwrap_or(tag);
    check_version(version)?;
    let name = file_name(version);
    let Some(size) = value["assets"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|asset| asset["name"].as_str() == Some(name.as_str()))
        .and_then(|asset| asset["size"].as_u64())
    else {
        return Ok(None);
    };
    let published = value["published_at"]
        .as_str()
        .unwrap_or_default()
        .chars()
        .take(10)
        .collect();
    let new = value["body"]
        .as_str()
        .unwrap_or_default()
        .lines()
        .map(|line| line.trim_start_matches(['#', '-', '*', ' ']).trim())
        .find(|line| !line.is_empty())
        .unwrap_or_default()
        .chars()
        .take(70)
        .collect();
    Ok(Some(Release {
        version: version.to_owned(),
        published,
        size,
        new,
    }))
}

fn tail(text: &str) -> String {
    text.trim().lines().last().unwrap_or_default().to_owned()
}

/// `update-check`: `done<TAB>VERSION<TAB>DATE<TAB>BYTES<TAB>NEW`, or
/// `done<TAB>none` when the latest release has no update file.
pub fn run_check<R: Runner>(runner: &R) -> Result<String, String> {
    let out = runner
        .run(
            Curl,
            &[
                "--silent",
                "--show-error",
                "--fail",
                "--location",
                "--max-time",
                "20",
                "--header",
                "Accept: application/vnd.github+json",
                API,
            ],
        )
        .map_err(|error| format!("{}: {error}", Curl.path()))?;
    if out.status != 0 {
        return Err(format!("GitHub cannot be reached: {}", tail(&out.stderr)));
    }
    Ok(match latest(&out.stdout)? {
        Some(r) => format!(
            "done\t{}\t{}\t{}\t{}",
            r.version,
            r.published,
            r.size,
            r.new.replace('\t', " ")
        ),
        None => "done\tnone".into(),
    })
}

/// Free bytes in `dir`, from `df`.
fn free<R: Runner>(runner: &R, dir: &Path) -> Option<u64> {
    let dir = dir.to_str()?;
    let out = runner
        .run(Df, &["-B1", "--output=avail", dir])
        .ok()
        .filter(|out| out.status == 0)?;
    out.stdout.lines().nth(1)?.trim().parse().ok()
}

/// `update-fetch VERSION`: downloads the update file; a partial download
/// goes on where it stopped. `done<TAB>PATH`.
pub fn run_fetch<R: Runner>(
    runner: &R,
    root: &Path,
    version: &str,
    size: Option<u64>,
) -> Result<String, String> {
    check_version(version)?;
    let dir = root.join(DIR);
    fs::create_dir_all(&dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    // The file, then its unpacked copy, then the repository moves in.
    if let (Some(size), Some(free)) = (size, free(runner, &dir))
        && free < size.saturating_mul(2) + (512 << 20)
    {
        return Err(format!(
            "not enough free space in /{DIR}: {} MB needed, {} MB free",
            (size * 2 + (512 << 20)) >> 20,
            free >> 20
        ));
    }
    let name = file_name(version);
    let file = dir.join(&name);
    let part = dir.join(format!("{name}.part"));
    let url = format!("{DOWNLOADS}/v{version}/{name}");
    let (Some(part_arg), Some(file_arg)) = (part.to_str(), file.to_str()) else {
        return Err("the download folder is not a plain path".into());
    };
    let out = runner
        .run(
            Curl,
            &[
                "--silent",
                "--show-error",
                "--fail",
                "--location",
                "--retry",
                "3",
                "--continue-at",
                "-",
                "--output",
                part_arg,
                &url,
            ],
        )
        .map_err(|error| format!("{}: {error}", Curl.path()))?;
    if out.status != 0 {
        return Err(format!("the download stopped: {}", tail(&out.stderr)));
    }
    fs::rename(&part, &file).map_err(|error| format!("{name}: {error}"))?;
    Ok(format!("done\t{file_arg}"))
}

/// Every file under `dir` as a path relative to it; a link or anything
/// but a file or a folder is refused.
fn files(dir: &Path, base: &Path, out: &mut BTreeSet<String>) -> Result<(), String> {
    for entry in fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))? {
        let entry = entry.map_err(|error| error.to_string())?;
        let kind = entry.file_type().map_err(|error| error.to_string())?;
        let path = entry.path();
        if kind.is_dir() {
            files(&path, base, out)?;
        } else if kind.is_file() {
            let rel = path.strip_prefix(base).map_err(|error| error.to_string())?;
            out.insert(rel.to_string_lossy().into_owned());
        } else {
            return Err(format!(
                "the update file holds a link or a special file ({}): it was altered",
                path.display()
            ));
        }
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buf = vec![0; 1 << 16];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hash.finalize().iter().map(|b| format!("{b:02x}")).collect())
}

/// The files `SHA256SUMS` lists, with their hashes (`HASH  PATH` lines).
pub fn sums(text: &str) -> Result<Vec<(String, String)>, String> {
    text.lines()
        .map(|line| {
            let (hash, path) = line
                .split_once("  ")
                .ok_or_else(|| format!("SHA256SUMS: not a checksum line: {line}"))?;
            let bad = hash.len() != 64
                || !hash.bytes().all(|b| b.is_ascii_hexdigit())
                || path.is_empty()
                || path.starts_with('/')
                || path.split('/').any(|part| part == ".." || part.is_empty());
            if bad {
                return Err(format!("SHA256SUMS: not a checksum line: {line}"));
            }
            Ok((hash.to_ascii_lowercase(), path.to_owned()))
        })
        .collect()
}

/// The signature: `gpgv` against a keyring made from the appliance's own
/// keys, so a key inside the file proves nothing.
fn signed<R: Runner>(runner: &R, root: &Path, tree: &Path, work: &Path) -> Result<(), String> {
    let mut keyring = Vec::new();
    let home = work.join("gnupg");
    fs::create_dir_all(&home).map_err(|error| format!("{}: {error}", home.display()))?;
    for key in KEYS {
        let path = root.join(key);
        if !path.exists() {
            continue;
        }
        let one = work.join(format!("key-{}.gpg", keyring.len()));
        let args = [
            "--batch",
            "--yes",
            "--no-options",
            "--homedir",
            home.to_str().unwrap_or_default(),
            "--dearmor",
            "--output",
            one.to_str().unwrap_or_default(),
            path.to_str().unwrap_or_default(),
        ];
        let out = runner
            .run(Gpg, &args)
            .map_err(|error| format!("{}: {error}", Gpg.path()))?;
        if out.status != 0 {
            return Err(format!("{key}: {}", tail(&out.stderr)));
        }
        keyring.push(fs::read(&one).map_err(|error| format!("{}: {error}", one.display()))?);
    }
    if keyring.is_empty() {
        return Err("this appliance has none of the OpenVIBES keys to check an update with".into());
    }
    let ring = work.join("keyring.gpg");
    fs::write(&ring, keyring.concat()).map_err(|error| format!("{}: {error}", ring.display()))?;
    let (asc, list) = (tree.join("SHA256SUMS.asc"), tree.join("SHA256SUMS"));
    let out = runner
        .run(
            Gpgv,
            &[
                "--status-fd",
                "1",
                "--keyring",
                ring.to_str().unwrap_or_default(),
                asc.to_str().unwrap_or_default(),
                list.to_str().unwrap_or_default(),
            ],
        )
        .map_err(|error| format!("{}: {error}", Gpgv.path()))?;
    let valid = out
        .stdout
        .lines()
        .any(|line| line.starts_with("[GNUPG:] VALIDSIG "));
    if out.status != 0 || !valid {
        return Err("the update file is not signed by OpenVIBES' key: it is corrupted or altered, nothing changed".into());
    }
    Ok(())
}

/// Checks an unpacked update file: the signature, every file against
/// `SHA256SUMS`, nothing it does not list, its version.
pub fn verify<R: Runner>(
    runner: &R,
    root: &Path,
    tree: &Path,
    work: &Path,
    version: &str,
) -> Result<(), String> {
    for name in [
        "SHA256SUMS",
        "SHA256SUMS.asc",
        "VERSION",
        "repo/repodata/repomd.xml",
    ] {
        if !tree.join(name).is_file() {
            return Err(format!("the update file is incomplete: {name} is missing"));
        }
    }
    signed(runner, root, tree, work)?;
    let listed = sums(&fs::read_to_string(tree.join("SHA256SUMS")).map_err(|e| e.to_string())?)?;
    let mut found = BTreeSet::new();
    files(tree, tree, &mut found)?;
    found.remove("SHA256SUMS");
    found.remove("SHA256SUMS.asc");
    let names: BTreeSet<String> = listed.iter().map(|(_, path)| path.clone()).collect();
    if names != found {
        return Err(
            "the update file holds files SHA256SUMS does not list, or lacks some: it was altered"
                .into(),
        );
    }
    for (hash, path) in &listed {
        if sha256(&tree.join(path))? != *hash {
            return Err(format!(
                "{path} does not match SHA256SUMS: the update file is corrupted or altered"
            ));
        }
    }
    let inside = fs::read_to_string(tree.join("VERSION")).map_err(|e| e.to_string())?;
    if inside.trim() != version {
        return Err(format!(
            "the update file is {}, not {version}",
            inside.trim()
        ));
    }
    Ok(())
}

/// `update-use VERSION`: unpacks the downloaded file, checks it, and makes
/// its repository the appliance's package source; the file and its copy
/// go. `done<TAB>VERSION`.
pub fn run_use<R: Runner>(runner: &R, root: &Path, version: &str) -> Result<String, String> {
    check_version(version)?;
    let dir = root.join(DIR);
    let file = dir.join(file_name(version));
    let work = dir.join(format!("{version}.new"));
    let _ = fs::remove_dir_all(&work);
    fs::create_dir_all(&work).map_err(|error| format!("{}: {error}", work.display()))?;
    let result = install(runner, root, &file, &work, version);
    let _ = fs::remove_dir_all(&work);
    if result.is_ok() {
        let _ = fs::remove_file(&file);
    }
    result
}

fn install<R: Runner>(
    runner: &R,
    root: &Path,
    file: &Path,
    work: &Path,
    version: &str,
) -> Result<String, String> {
    let unpacked = work.join("files");
    fs::create_dir_all(&unpacked).map_err(|error| format!("{}: {error}", unpacked.display()))?;
    let out = runner
        .run(
            Tar,
            &[
                "--extract",
                "--no-same-owner",
                "--no-same-permissions",
                "--file",
                file.to_str().unwrap_or_default(),
                "--directory",
                unpacked.to_str().unwrap_or_default(),
            ],
        )
        .map_err(|error| format!("{}: {error}", Tar.path()))?;
    if out.status != 0 {
        return Err(format!(
            "the update file cannot be unpacked: {}",
            tail(&out.stderr)
        ));
    }
    // Nothing but the one folder at the top.
    let mut top = BTreeSet::new();
    for entry in fs::read_dir(&unpacked).map_err(|e| e.to_string())? {
        top.insert(entry.map_err(|e| e.to_string())?.file_name());
    }
    if top.len() != 1 || !top.contains(std::ffi::OsStr::new(TREE)) {
        return Err(format!(
            "the update file holds more than {TREE}/: it was altered"
        ));
    }
    let tree = unpacked.join(TREE);
    verify(runner, root, &tree, work, version)?;
    swap(root, &tree.join("repo"))?;
    Ok(format!("done\t{version}"))
}

/// The new repository in the package source's place; the old one goes
/// once the new is there (one rename each, on the same file system).
fn swap(root: &Path, new: &Path) -> Result<(), String> {
    let repo = root.join(REPO);
    let old: PathBuf = repo.with_extension("old");
    let _ = fs::remove_dir_all(&old);
    if repo.exists() {
        fs::rename(&repo, &old).map_err(|error| format!("{}: {error}", repo.display()))?;
    }
    if let Some(parent) = repo.parent() {
        fs::create_dir_all(parent).map_err(|error| format!("{}: {error}", parent.display()))?;
    }
    if let Err(error) = fs::rename(new, &repo) {
        // The old source comes back: the appliance keeps a working one.
        let _ = fs::rename(&old, &repo);
        return Err(format!("{}: {error}", repo.display()));
    }
    let _ = fs::remove_dir_all(&old);
    Ok(())
}

#[cfg(test)]
#[path = "appliance_update_tests.rs"]
mod tests;
