//! The bundle reader keeps to the format: `feed.json` first, then regular
//! `blobs/<sha256>` files whose names are their own hashes.

use std::path::PathBuf;

use openvibes_vulns::{
    bundle::{self, Allowed},
    feedfmt::hex,
};
use sha2::{Digest, Sha256};

fn header(name: &str, size: usize, kind: u8) -> [u8; 512] {
    let mut block = [0u8; 512];
    block[..name.len()].copy_from_slice(name.as_bytes());
    block[100..107].copy_from_slice(b"0000644");
    block[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    block[156] = kind;
    block[148..156].fill(b' ');
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    block
}

fn entry(out: &mut Vec<u8>, name: &str, data: &[u8], kind: u8) {
    out.extend_from_slice(&header(name, data.len(), kind));
    out.extend_from_slice(data);
    out.resize(out.len().div_ceil(512) * 512, 0);
}

fn tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, data) in entries {
        entry(&mut out, name, data, b'0');
    }
    out.extend_from_slice(&[0u8; 1024]);
    out
}

fn blob_name(data: &[u8]) -> String {
    format!("blobs/{}", hex(&Sha256::digest(data)))
}

struct Dirs(PathBuf);

impl Dirs {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ov-bundle-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("work")).unwrap();
        Self(dir)
    }

    fn write(&self, bytes: &[u8]) -> PathBuf {
        let path = self.0.join("bundle.tar");
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn work(&self) -> PathBuf {
        self.0.join("work")
    }
}

impl Drop for Dirs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Every blob named in `entries` is allowed, up to `limit` bytes.
fn allow(names: &[&str], limit: u64) -> impl FnOnce(&[u8]) -> Result<Allowed, String> {
    let allowed: Allowed = names
        .iter()
        .map(|n| (n.strip_prefix("blobs/").unwrap_or(n).to_owned(), limit))
        .collect();
    move |_| Ok(allowed)
}

fn refused(name: &str, bytes: &[u8], names: &[&str]) -> String {
    let dirs = Dirs::new(name);
    let error =
        bundle::unpack_tar(&dirs.write(bytes), &dirs.work(), allow(names, 1 << 20)).unwrap_err();
    error.to_string()
}

#[test]
fn a_well_formed_bundle_is_unpacked_by_hash() {
    let dirs = Dirs::new("good");
    let blob = b"some feed file";
    let name = blob_name(blob);
    let unpacked = bundle::unpack_tar(
        &dirs.write(&tar(&[("feed.json", b"{}"), (&name, blob)])),
        &dirs.work(),
        allow(&[&name], 1 << 20),
    )
    .unwrap();
    assert_eq!(unpacked.envelope, b"{}");
    let hex = name.strip_prefix("blobs/").unwrap();
    assert_eq!(std::fs::read(unpacked.blob(hex).unwrap()).unwrap(), blob);
    assert!(unpacked.blob(&"0".repeat(64)).is_none());
}

#[test]
fn feed_json_must_come_first() {
    let blob = b"x";
    let name = blob_name(blob);
    let said = refused(
        "order",
        &tar(&[(&name, blob), ("feed.json", b"{}")]),
        &[&name],
    );
    assert!(said.contains("feed.json must come first"), "{said}");
}

#[test]
fn only_regular_files_with_blob_names_are_taken() {
    let blob = b"x";
    let name = blob_name(blob);
    let mut link = Vec::new();
    entry(&mut link, "feed.json", b"{}", b'0');
    entry(&mut link, &name, b"", b'2'); // a symbolic link
    link.extend_from_slice(&[0u8; 1024]);
    assert!(refused("link", &link, &[&name]).contains("only regular files"));
    for odd in [
        "../etc/passwd",
        "blobs/../x",
        "extra.txt",
        "blobs/ABC",
        "/abs",
    ] {
        let said = refused("odd", &tar(&[("feed.json", b"{}"), (odd, b"x")]), &[]);
        assert!(said.contains("neither feed.json nor"), "{odd}: {said}");
    }
}

#[test]
fn a_blob_must_be_named_by_its_own_hash() {
    let wrong = format!("blobs/{}", "0".repeat(64));
    let said = refused(
        "hash",
        &tar(&[("feed.json", b"{}"), (&wrong, b"x")]),
        &[&wrong],
    );
    assert!(said.contains("own SHA-256"), "{said}");
}

#[test]
fn a_blob_the_manifest_does_not_name_is_refused_before_it_is_written() {
    let blob = b"x";
    let name = blob_name(blob);
    let dirs = Dirs::new("unnamed");
    let path = dirs.write(&tar(&[("feed.json", b"{}"), (&name, blob)]));
    let said = bundle::unpack_tar(&path, &dirs.work(), allow(&[], 10))
        .unwrap_err()
        .to_string();
    assert!(said.contains("does not name"), "{said}");
    assert_eq!(std::fs::read_dir(dirs.work()).unwrap().count(), 0);
}

#[test]
fn a_refused_feed_json_stops_the_reader_before_any_blob() {
    let blob = b"x";
    let name = blob_name(blob);
    let dirs = Dirs::new("refused");
    let path = dirs.write(&tar(&[("feed.json", b"{}"), (&name, blob)]));
    let said = bundle::unpack_tar(&path, &dirs.work(), |_| Err("feed refused: nope".into()))
        .unwrap_err()
        .to_string();
    assert_eq!(said, "feed refused: nope");
    assert_eq!(std::fs::read_dir(dirs.work()).unwrap().count(), 0);
}

#[test]
fn a_blob_twice_or_too_much_data_or_a_cut_archive_is_refused() {
    let blob = b"x";
    let name = blob_name(blob);
    let twice = tar(&[("feed.json", b"{}"), (&name, blob), (&name, blob)]);
    assert!(refused("twice", &twice, &[&name]).contains("appears twice"));

    let dirs = Dirs::new("big");
    let big = vec![1u8; 4096];
    let name = blob_name(&big);
    let path = dirs.write(&tar(&[("feed.json", b"{}"), (&name, &big)]));
    assert!(bundle::unpack_tar(&path, &dirs.work(), allow(&[&name], 1000)).is_err());

    let mut cut = tar(&[("feed.json", b"{}"), (&name, &big)]);
    cut.truncate(512 + 512 + 512 + 100);
    assert!(refused("cut", &cut, &[&name]).contains("ends inside"));

    let mut tail = tar(&[("feed.json", b"{}")]);
    tail.extend_from_slice(&[1u8; 512]);
    assert!(refused("tail", &tail, &[]).contains("after the end"));
}

#[test]
fn a_bad_checksum_and_a_missing_feed_json_are_refused() {
    let mut bad = tar(&[("feed.json", b"{}")]);
    bad[0] = b'g';
    assert!(refused("sum", &bad, &[]).contains("checksum"));
    assert!(refused("empty", &[0u8; 1024], &[]).contains("feed.json is missing"));
}

#[test]
fn an_oversized_envelope_is_left_for_the_verifier_to_name() {
    let dirs = Dirs::new("env");
    let huge = vec![b'a'; (1 << 20) + 5];
    let unpacked = bundle::unpack_tar(
        &dirs.write(&tar(&[("feed.json", &huge)])),
        &dirs.work(),
        allow(&[], 0),
    )
    .unwrap();
    assert_eq!(unpacked.envelope.len(), (1 << 20) + 1);
}

fn tree(dirs: &Dirs, blob: &[u8]) -> (String, PathBuf) {
    let hex = hex(&Sha256::digest(blob));
    let tree = dirs.0.join("tree");
    std::fs::create_dir_all(tree.join("blobs")).unwrap();
    std::fs::write(tree.join("feed.json"), b"{}").unwrap();
    std::fs::write(tree.join("blobs").join(&hex), blob).unwrap();
    (hex, tree)
}

#[test]
fn an_unpacked_tree_is_copied_so_later_changes_to_it_do_not_matter() {
    let dirs = Dirs::new("tree");
    let (hex, tree) = tree(&dirs, b"signed bytes");
    let unpacked = bundle::open_dir(&tree, &dirs.work(), allow(&[&hex], 100)).unwrap();
    assert_eq!(unpacked.envelope, b"{}");
    std::fs::write(tree.join("blobs").join(&hex), b"swapped").unwrap();
    assert_eq!(
        std::fs::read(unpacked.blob(&hex).unwrap()).unwrap(),
        b"signed bytes"
    );
    assert!(bundle::open_dir(&dirs.work(), &dirs.work(), allow(&[], 0)).is_err());
}

#[test]
fn a_tree_blob_that_is_wrong_too_large_or_a_link_is_left_out() {
    let dirs = Dirs::new("tree-bad");
    let (hex, tree) = tree(&dirs, b"signed bytes");
    // Content that does not hash to its name.
    std::fs::write(tree.join("blobs").join(&hex), b"tampered").unwrap();
    let unpacked = bundle::open_dir(&tree, &dirs.work(), allow(&[&hex], 100)).unwrap();
    assert!(unpacked.blob(&hex).is_none());
    // Larger than the manifest's size.
    std::fs::write(tree.join("blobs").join(&hex), b"signed bytes").unwrap();
    let work = dirs.0.join("work2");
    std::fs::create_dir_all(&work).unwrap();
    let unpacked = bundle::open_dir(&tree, &work, allow(&[&hex], 3)).unwrap();
    assert!(unpacked.blob(&hex).is_none());
    // A symbolic link in place of the blob.
    std::fs::remove_file(tree.join("blobs").join(&hex)).unwrap();
    std::os::unix::fs::symlink("/etc/hostname", tree.join("blobs").join(&hex)).unwrap();
    let work = dirs.0.join("work3");
    std::fs::create_dir_all(&work).unwrap();
    let unpacked = bundle::open_dir(&tree, &work, allow(&[&hex], 1 << 20)).unwrap();
    assert!(unpacked.blob(&hex).is_none());
}
