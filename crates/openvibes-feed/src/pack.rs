//! Packing a built tree into one tar for carrying into a network with no
//! route to the mirror: `feed.json` first, then each blob it names.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use openvibes_vulns::{feedfmt, repodata::hex};
use sha2::{Digest, Sha256};

fn header(name: &str, size: u64) -> [u8; 512] {
    let mut block = [0u8; 512];
    block[..name.len()].copy_from_slice(name.as_bytes());
    block[100..107].copy_from_slice(b"0000644");
    block[108..115].copy_from_slice(b"0000000");
    block[116..123].copy_from_slice(b"0000000");
    block[124..135].copy_from_slice(format!("{size:011o}").as_bytes());
    block[136..147].copy_from_slice(b"00000000000");
    block[156] = b'0';
    block[257..263].copy_from_slice(b"ustar\0");
    block[263..265].copy_from_slice(b"00");
    block[148..156].fill(b' ');
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    block
}

fn pad(out: &mut File, size: u64) -> Result<(), String> {
    let rest = usize::try_from(size % 512).unwrap_or(0);
    if rest > 0 {
        out.write_all(&vec![0u8; 512 - rest])
            .map_err(|e| format!("cannot write the bundle: {e}"))?;
    }
    Ok(())
}

/// The SHA-256 hex names of the blobs `feed.json` lists.
fn named_blobs(envelope: &[u8]) -> Result<BTreeSet<String>, String> {
    let value: serde_json::Value =
        serde_json::from_slice(envelope).map_err(|_| "feed.json is not readable")?;
    let manifest = value["manifest"]
        .as_str()
        .ok_or("feed.json has no manifest")?;
    let manifest: serde_json::Value =
        serde_json::from_str(manifest).map_err(|_| "the manifest is not readable")?;
    manifest["files"]
        .as_array()
        .ok_or("the manifest has no files")?
        .iter()
        .map(|file| {
            file["sha256"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "a file has no sha256".to_owned())
        })
        .collect()
}

/// Packs `dir` (a tree from `build`) into the new file `out`; returns the
/// number of blobs. Each blob is checked against its name as it is copied.
///
/// # Errors
/// The tree is incomplete or damaged, or `out` exists or cannot be written.
pub fn bundle(dir: &Path, out: &Path) -> Result<usize, String> {
    let path = dir.join("feed.json");
    if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
        return Err(format!("{} is not a regular file", path.display()));
    }
    let mut envelope = Vec::new();
    File::open(&path)
        .and_then(|f| {
            f.take(feedfmt::MAX_ENVELOPE as u64 + 1)
                .read_to_end(&mut envelope)
        })
        .map_err(|e| format!("cannot read feed.json: {e}"))?;
    if envelope.len() > feedfmt::MAX_ENVELOPE {
        return Err("feed.json is over 1 MiB".into());
    }
    let names = named_blobs(&envelope)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    let result = (|| {
        file.write_all(&header("feed.json", envelope.len() as u64))
            .and_then(|()| file.write_all(&envelope))
            .map_err(|e| format!("cannot write the bundle: {e}"))?;
        pad(&mut file, envelope.len() as u64)?;
        for name in &names {
            let source = dir.join("blobs").join(name);
            let meta = fs::symlink_metadata(&source)
                .ok()
                .filter(fs::Metadata::is_file)
                .ok_or_else(|| format!("blob {name} is missing from {}", dir.display()))?;
            file.write_all(&header(&format!("blobs/{name}"), meta.len()))
                .map_err(|e| format!("cannot write the bundle: {e}"))?;
            let mut input =
                File::open(&source).map_err(|e| format!("cannot read blob {name}: {e}"))?;
            let (mut hasher, mut left) = (Sha256::new(), meta.len());
            let mut buffer = vec![0u8; 1 << 16];
            while left > 0 {
                let take = usize::try_from(left.min(buffer.len() as u64)).unwrap_or(buffer.len());
                input
                    .read_exact(&mut buffer[..take])
                    .map_err(|e| format!("cannot read blob {name}: {e}"))?;
                hasher.update(&buffer[..take]);
                file.write_all(&buffer[..take])
                    .map_err(|e| format!("cannot write the bundle: {e}"))?;
                left -= take as u64;
            }
            if hex(&hasher.finalize()) != *name {
                return Err(format!("blob {name} does not match its name"));
            }
            pad(&mut file, meta.len())?;
        }
        file.write_all(&[0u8; 1024])
            .map_err(|e| format!("cannot write the bundle: {e}"))?;
        Ok(names.len())
    })();
    if result.is_err() {
        let _ = fs::remove_file(out);
    }
    result
}
