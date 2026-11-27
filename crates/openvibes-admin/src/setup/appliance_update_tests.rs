//! The update file's check (#674): GitHub's answer, the version, the
//! checksum list, and a real gpg/gpgv signature on a small tree.
// Tests only: tar and gpgconf build the fixtures (clippy.toml).
#![allow(clippy::disallowed_types)]

use std::{fs, path::Path};

use platform_host::runner::{Program::Gpg, Runner, SystemRunner};

use super::{Release, check_version, latest, run_use, sums, verify};

#[test]
fn the_latest_release_and_its_update_file() {
    let json = r##"{"tag_name":"v0.3.3","published_at":"2026-12-02T10:00:00Z",
        "body":"# What's new\n- offline updates over SFTP · fixes\n",
        "assets":[{"name":"openvibes-agent-0.3.3.rpm","size":1},
                  {"name":"openvibes-appliance-update-0.3.3.tar","size":312000000}]}"##;
    assert_eq!(
        latest(json).unwrap(),
        Some(Release {
            version: "0.3.3".into(),
            published: "2026-12-02".into(),
            size: 312_000_000,
            new: "What's new".into(),
        })
    );
    let without = r#"{"tag_name":"v0.3.3","assets":[]}"#;
    assert_eq!(latest(without).unwrap(), None);
    assert!(latest(r#"{"tag_name":"v../../etc"}"#).is_err());
}

#[test]
fn versions_are_never_paths() {
    assert!(check_version("0.3.3").is_ok());
    assert!(check_version("0.3.3-rc.1").is_ok());
    for bad in ["", "../x", "0.3/3", "v0.3.3", "0.3.3 x"] {
        assert!(check_version(bad).is_err(), "{bad}");
    }
}

#[test]
fn checksum_lines_must_be_plain() {
    let hash = "a".repeat(64);
    assert_eq!(
        sums(&format!("{hash}  repo/x.rpm\n")).unwrap(),
        [(hash.clone(), "repo/x.rpm".into())]
    );
    for bad in ["../x", "/etc/x", "repo//x", ""] {
        assert!(sums(&format!("{hash}  {bad}")).is_err(), "{bad}");
    }
    assert!(sums("xyz  repo/x").is_err());
}

/// gpg with its own home: makes a key, signs, exports. `None` without gpg.
fn gpg(home: &Path, args: &[&str]) -> Option<String> {
    let mut all = vec!["--batch", "--quiet", "--homedir", home.to_str()?];
    all.extend_from_slice(args);
    let out = SystemRunner.run(Gpg, &all).ok()?;
    (out.status == 0).then_some(out.stdout)
}

/// A signed update tree under `root`, and the appliance's key installed.
fn signed_tree(root: &Path) -> Option<std::path::PathBuf> {
    let home = root.join("signer");
    fs::create_dir_all(&home).ok()?;
    let mode = std::os::unix::fs::PermissionsExt::from_mode(0o700);
    fs::set_permissions(&home, mode).ok()?;
    gpg(
        &home,
        &[
            "--passphrase",
            "",
            "--quick-gen-key",
            "test",
            "ed25519",
            "sign",
            "never",
        ],
    )?;
    let key = gpg(&home, &["--armor", "--export"])?;
    let keys = root.join("etc/pki/rpm-gpg");
    fs::create_dir_all(&keys).ok()?;
    fs::write(keys.join("RPM-GPG-KEY-openvibes-appliance"), key).ok()?;
    let tree = root.join("tree");
    fs::create_dir_all(tree.join("repo/repodata")).ok()?;
    fs::write(tree.join("repo/repodata/repomd.xml"), "<repomd/>").ok()?;
    fs::write(tree.join("repo/openvibes-admin-0.3.3.rpm"), "rpm").ok()?;
    fs::write(tree.join("VERSION"), "0.3.3\n").ok()?;
    let mut list = String::new();
    for path in [
        "VERSION",
        "repo/openvibes-admin-0.3.3.rpm",
        "repo/repodata/repomd.xml",
    ] {
        list.push_str(&format!(
            "{}  {path}\n",
            super::sha256(&tree.join(path)).ok()?
        ));
    }
    fs::write(tree.join("SHA256SUMS"), list).ok()?;
    let asc = tree.join("SHA256SUMS.asc");
    let sums = tree.join("SHA256SUMS");
    gpg(
        &home,
        &[
            "--detach-sign",
            "--armor",
            "--output",
            asc.to_str()?,
            sums.to_str()?,
        ],
    )?;
    let _ = std::process::Command::new("gpgconf")
        .args(["--homedir", home.to_str()?, "--kill", "all"])
        .status();
    Some(tree)
}

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ov-update-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn only_a_file_signed_by_the_appliances_key_and_unchanged_passes() {
    let root = temp("verify");
    let Some(tree) = signed_tree(&root) else {
        eprintln!("no gpg here: skipped");
        return;
    };
    let work = root.join("work");
    fs::create_dir_all(&work).unwrap();
    verify(&SystemRunner, &root, &tree, &work, "0.3.3").unwrap();
    assert!(
        verify(&SystemRunner, &root, &tree, &work, "0.3.4").is_err(),
        "another version"
    );

    // A changed package.
    fs::write(tree.join("repo/openvibes-admin-0.3.3.rpm"), "evil").unwrap();
    let error = verify(&SystemRunner, &root, &tree, &work, "0.3.3").unwrap_err();
    assert!(error.contains("does not match SHA256SUMS"), "{error}");
    fs::write(tree.join("repo/openvibes-admin-0.3.3.rpm"), "rpm").unwrap();

    // A file the list does not name, and a link.
    fs::write(tree.join("repo/extra.rpm"), "x").unwrap();
    assert!(
        verify(&SystemRunner, &root, &tree, &work, "0.3.3")
            .unwrap_err()
            .contains("does not list")
    );
    fs::remove_file(tree.join("repo/extra.rpm")).unwrap();
    std::os::unix::fs::symlink("/etc/shadow", tree.join("repo/link")).unwrap();
    assert!(
        verify(&SystemRunner, &root, &tree, &work, "0.3.3")
            .unwrap_err()
            .contains("link")
    );
    fs::remove_file(tree.join("repo/link")).unwrap();

    // The list changed after signing.
    let list = fs::read_to_string(tree.join("SHA256SUMS")).unwrap();
    fs::write(tree.join("SHA256SUMS"), format!("{list}\n")).unwrap();
    assert!(
        verify(&SystemRunner, &root, &tree, &work, "0.3.3")
            .unwrap_err()
            .contains("not signed")
    );
    fs::write(tree.join("SHA256SUMS"), list).unwrap();

    // Signed, but by a key this appliance was not installed with.
    let other = temp("verify-other");
    signed_tree(&other).unwrap();
    fs::copy(
        other.join("etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes-appliance"),
        root.join("etc/pki/rpm-gpg/RPM-GPG-KEY-openvibes-appliance"),
    )
    .unwrap();
    assert!(
        verify(&SystemRunner, &root, &tree, &work, "0.3.3")
            .unwrap_err()
            .contains("not signed")
    );
    let _ = fs::remove_dir_all(&other);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn a_checked_file_becomes_the_package_source() {
    let root = temp("use");
    let Some(tree) = signed_tree(&root) else {
        eprintln!("no gpg here: skipped");
        return;
    };
    // The file as a release carries it.
    let dir = root.join(super::DIR);
    fs::create_dir_all(&dir).unwrap();
    let staged = root.join("stage");
    fs::create_dir_all(&staged).unwrap();
    fs::rename(&tree, staged.join("openvibes-appliance-update")).unwrap();
    let status = std::process::Command::new("tar")
        .args(["-C", staged.to_str().unwrap(), "-cf"])
        .arg(dir.join(super::file_name("0.3.3")))
        .arg("openvibes-appliance-update")
        .status()
        .unwrap();
    assert!(status.success());
    fs::create_dir_all(root.join(super::REPO)).unwrap();
    fs::write(root.join(super::REPO).join("old.rpm"), "old").unwrap();

    assert_eq!(
        run_use(&SystemRunner, &root, "0.3.3").unwrap(),
        "done\t0.3.3"
    );
    let repo = root.join(super::REPO);
    assert!(repo.join("openvibes-admin-0.3.3.rpm").is_file());
    assert!(!repo.join("old.rpm").exists(), "the old source is gone");
    assert!(
        !dir.join(super::file_name("0.3.3")).exists(),
        "the file is removed"
    );
    assert!(!dir.join("0.3.3.new").exists(), "and its unpacked copy");
    let _ = fs::remove_dir_all(&root);
}
