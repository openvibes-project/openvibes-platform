//! Reading a feed from a tar bundle or an unpacked tree (openvibes-protocol
//! `spec/feed-v1.md`, "Bundle (tar)"): `feed.json` first, then blobs named by
//! their own SHA-256. Only regular files with exactly those names are taken;
//! each blob is copied under the name its content hashes to, never under a
//! path read from the archive.

use std::{
    collections::HashMap,
    fmt,
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::feedfmt::{self, MAX_ENVELOPE, MAX_FILES};

/// The blobs a verified feed names, by lowercase hex SHA-256, with the most
/// bytes each may have.
pub type Allowed = HashMap<String, u64>;

const BLOCK: usize = 512;

/// A feed on disk: its `feed.json` and the directory holding `<sha256>` blobs.
#[derive(Debug)]
pub struct Unpacked {
    /// The bytes of `feed.json` (at most one byte over the 1 MiB limit, so
    /// the verifier refuses an oversized one).
    pub envelope: Vec<u8>,
    /// Directory with one regular file per blob, named by its SHA-256.
    pub blobs: PathBuf,
}

impl Unpacked {
    /// The file for the blob with this lowercase hex SHA-256, if it is a
    /// regular file (a link is not followed).
    #[must_use]
    pub fn blob(&self, sha256: &str) -> Option<PathBuf> {
        let path = self.blobs.join(sha256);
        let meta = std::fs::symlink_metadata(&path).ok()?;
        meta.is_file().then_some(path)
    }
}

/// Why a bundle or tree was not read.
#[derive(Debug)]
pub enum BundleError {
    /// A file could not be read or written.
    Io(String),
    /// The archive breaks a rule of the format.
    Format(&'static str),
    /// More data than the limits allow.
    TooLarge,
    /// The feed was refused before any blob was taken; the text says why.
    Refused(String),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(message) => f.write_str(message),
            Self::Format(message) => write!(f, "not a valid bundle: {message}"),
            Self::TooLarge => f.write_str("the bundle is larger than the limits allow"),
            Self::Refused(message) => f.write_str(message),
        }
    }
}

fn io_error(what: &str, error: &io::Error) -> BundleError {
    BundleError::Io(format!("{what}: {error}"))
}

fn blob_name(name: &str) -> Option<&str> {
    let hex = name.strip_prefix("blobs/")?;
    (hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))).then_some(hex)
}

fn octal(field: &[u8]) -> Option<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        return None; // base-256 sizes are not part of the format
    }
    let text: Vec<u8> = field
        .iter()
        .copied()
        .take_while(|&b| b != 0 && b != b' ')
        .collect();
    if text.is_empty() {
        return Some(0);
    }
    u64::from_str_radix(std::str::from_utf8(&text).ok()?, 8).ok()
}

fn read_exact_or_end(reader: &mut impl Read, block: &mut [u8; BLOCK]) -> Result<bool, BundleError> {
    let mut filled = 0;
    while filled < BLOCK {
        match reader.read(&mut block[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => return Err(BundleError::Format("the archive ends inside a block")),
            Ok(n) => filled += n,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io_error("cannot read the bundle", &error)),
        }
    }
    Ok(true)
}

/// Reads `file` (a plain tar) into `work`, an existing empty directory the
/// caller owns. `feed.json` is read first and handed to `verify`, which
/// returns the blobs it names (or refuses the feed); no blob is written
/// before that. Only the blobs it names are copied, each to `work/<sha256>`
/// and no larger than its limit.
///
/// # Errors
/// Any rule of the format broken, a limit passed, the feed refused by
/// `verify`, or an I/O failure.
pub fn unpack_tar(
    file: &Path,
    work: &Path,
    verify: impl FnOnce(&[u8]) -> Result<Allowed, String>,
) -> Result<Unpacked, BundleError> {
    let mut reader = File::open(file).map_err(|e| io_error("cannot open the bundle", &e))?;
    let mut envelope = None;
    let mut verify = Some(verify);
    let mut allowed = Allowed::new();
    let mut entries = 0usize;
    let mut block = [0u8; BLOCK];
    loop {
        if !read_exact_or_end(&mut reader, &mut block)? {
            break; // a clean end without the closing zero blocks
        }
        if block.iter().all(|&b| b == 0) {
            // The archive ends here; only zeros may follow.
            let mut rest = [0u8; BLOCK];
            for _ in 0..20 {
                if !read_exact_or_end(&mut reader, &mut rest)? {
                    break;
                }
                if rest.iter().any(|&b| b != 0) {
                    return Err(BundleError::Format("data after the end of the archive"));
                }
            }
            break;
        }
        entries += 1;
        if entries > MAX_FILES + 1 {
            return Err(BundleError::Format("too many entries"));
        }
        let checksum: u32 = block
            .iter()
            .enumerate()
            .map(|(i, &b)| {
                if (148..156).contains(&i) {
                    u32::from(b' ')
                } else {
                    u32::from(b)
                }
            })
            .sum();
        let stored = octal(&block[148..156]).ok_or(BundleError::Format("bad header checksum"))?;
        if u64::from(checksum) != stored {
            return Err(BundleError::Format("bad header checksum"));
        }
        if !matches!(block[156], b'0' | 0) {
            return Err(BundleError::Format("only regular files are allowed"));
        }
        if block[345..500].iter().any(|&b| b != 0) {
            return Err(BundleError::Format(
                "entry names with a prefix are not allowed",
            ));
        }
        let name_end = block[..100].iter().position(|&b| b == 0).unwrap_or(100);
        let name = std::str::from_utf8(&block[..name_end])
            .map_err(|_| BundleError::Format("an entry name is not text"))?
            .to_owned();
        let size = octal(&block[124..136]).ok_or(BundleError::Format("bad entry size"))?;
        let padded = size.div_ceil(BLOCK as u64) * BLOCK as u64;
        if entries == 1 {
            if name != "feed.json" {
                return Err(BundleError::Format("feed.json must come first"));
            }
            if size > MAX_ENVELOPE as u64 {
                // Keep one byte over so the verifier names it bad_format.
                envelope = Some(vec![b' '; MAX_ENVELOPE + 1]);
            } else {
                let mut data = vec![0u8; usize::try_from(size).map_err(|_| BundleError::TooLarge)?];
                reader
                    .read_exact(&mut data)
                    .map_err(|e| io_error("cannot read the bundle", &e))?;
                envelope = Some(data);
            }
            skip(
                &mut reader,
                if size > MAX_ENVELOPE as u64 {
                    padded
                } else {
                    padded - size
                },
            )?;
            if let (Some(verify), Some(bytes)) = (verify.take(), envelope.as_deref()) {
                allowed = verify(bytes).map_err(BundleError::Refused)?;
            }
            continue;
        }
        let hex = blob_name(&name).ok_or(BundleError::Format(
            "an entry is neither feed.json nor blobs/<sha256>",
        ))?;
        let limit = allowed.get(hex).ok_or(BundleError::Format(
            "an entry is a blob the manifest does not name",
        ))?;
        if size > *limit {
            return Err(BundleError::TooLarge);
        }
        let path = work.join(hex);
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|e| {
                if e.kind() == io::ErrorKind::AlreadyExists {
                    BundleError::Format("a blob appears twice")
                } else {
                    io_error("cannot write a blob", &e)
                }
            })?;
        let mut hasher = Sha256::new();
        let mut left = size;
        let mut buffer = vec![0u8; 1 << 16];
        while left > 0 {
            let take = usize::try_from(left.min(buffer.len() as u64)).unwrap_or(buffer.len());
            reader
                .read_exact(&mut buffer[..take])
                .map_err(|_| BundleError::Format("the archive ends inside a file"))?;
            hasher.update(&buffer[..take]);
            out.write_all(&buffer[..take])
                .map_err(|e| io_error("cannot write a blob", &e))?;
            left -= take as u64;
        }
        out.flush()
            .map_err(|e| io_error("cannot write a blob", &e))?;
        if feedfmt::hex(&hasher.finalize()) != hex {
            return Err(BundleError::Format(
                "a blob is not named by its own SHA-256",
            ));
        }
        skip(&mut reader, padded - size)?;
    }
    Ok(Unpacked {
        envelope: envelope.ok_or(BundleError::Format("feed.json is missing"))?,
        blobs: work.to_owned(),
    })
}

fn skip(reader: &mut impl Read, count: u64) -> Result<(), BundleError> {
    let copied = io::copy(&mut reader.by_ref().take(count), &mut io::sink())
        .map_err(|e| io_error("cannot read the bundle", &e))?;
    if copied == count {
        Ok(())
    } else {
        Err(BundleError::Format("the archive ends inside a file"))
    }
}

/// Reads an unpacked tree, `dir/feed.json` and `dir/blobs/<sha256>`, the
/// way a tar is read: `feed.json` goes to `verify`, then each blob it names
/// is copied into `work` while its SHA-256 is computed, and only that copy is
/// used afterwards (the tree may be writable by others). A blob that is
/// missing, is not a regular file, is too large or does not hash to its name
/// is left out; the importer then reports the file as refused.
///
/// # Errors
/// `feed.json` is not a regular file or cannot be read, the feed is refused
/// by `verify`, or an I/O failure.
pub fn open_dir(
    dir: &Path,
    work: &Path,
    verify: impl FnOnce(&[u8]) -> Result<Allowed, String>,
) -> Result<Unpacked, BundleError> {
    let path = dir.join("feed.json");
    let meta =
        std::fs::symlink_metadata(&path).map_err(|e| io_error("cannot read feed.json", &e))?;
    if !meta.is_file() {
        return Err(BundleError::Format("feed.json is not a regular file"));
    }
    let mut envelope = Vec::new();
    File::open(&path)
        .and_then(|file| {
            file.take(MAX_ENVELOPE as u64 + 1)
                .read_to_end(&mut envelope)
        })
        .map_err(|e| io_error("cannot read feed.json", &e))?;
    let allowed = verify(&envelope).map_err(BundleError::Refused)?;
    let blobs = dir.join("blobs");
    let tree_ok = std::fs::symlink_metadata(&blobs).is_ok_and(|m| m.is_dir());
    for (hex, limit) in allowed.iter().filter(|_| tree_ok) {
        let source = blobs.join(hex);
        if !std::fs::symlink_metadata(&source).is_ok_and(|m| m.is_file()) {
            continue;
        }
        let Ok(input) = File::open(&source) else {
            continue;
        };
        let target = work.join(hex);
        let mut out = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&target)
            .map_err(|e| io_error("cannot write a blob", &e))?;
        let mut hasher = Sha256::new();
        let mut reader = input.take(limit + 1);
        let mut buffer = vec![0u8; 1 << 16];
        let mut length = 0u64;
        loop {
            let read = reader
                .read(&mut buffer)
                .map_err(|e| io_error("cannot read a blob", &e))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            out.write_all(&buffer[..read])
                .map_err(|e| io_error("cannot write a blob", &e))?;
            length += read as u64;
        }
        drop(out);
        if length > *limit || feedfmt::hex(&hasher.finalize()) != *hex {
            std::fs::remove_file(&target).map_err(|e| io_error("cannot remove a blob", &e))?;
        }
    }
    Ok(Unpacked {
        envelope,
        blobs: work.to_owned(),
    })
}
