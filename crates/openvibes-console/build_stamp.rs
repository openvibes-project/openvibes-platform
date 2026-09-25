use std::{
    collections::BTreeSet,
    fmt::Write,
    fs,
    path::{Component, Path},
};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{read_regular_file, read_regular_nonempty, string_array, validate_relative_path};

const STAMP_PATH: &str = "web/dist/build-stamp.json";
const INPUT_IGNORED_DIRECTORIES: &[&str] = &[
    "coverage",
    "dist",
    "node_modules",
    "playwright-report",
    "test-results",
];
const OUTPUT_IGNORED_FILES: &[&str] = &[".gitkeep", "build-stamp.json"];

pub(super) fn input_files(web: &Path) -> Result<Vec<String>, String> {
    collect_files(web, INPUT_IGNORED_DIRECTORIES, &[])
}

pub(super) fn validate_build_stamp(crate_dir: &Path) -> Result<(), String> {
    let bytes = read_regular_nonempty(&crate_dir.join(STAMP_PATH), "frontend build stamp")?;
    let stamp: Value =
        serde_json::from_slice(&bytes).map_err(|error| format!("invalid {STAMP_PATH}: {error}"))?;
    let object = stamp
        .as_object()
        .ok_or_else(|| format!("{STAMP_PATH} must be an object"))?;
    let expected = BTreeSet::from([
        "algorithm",
        "inputDigest",
        "inputFiles",
        "outputDigest",
        "outputFiles",
        "version",
    ]);
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected
        || object.get("version") != Some(&Value::from(1))
        || object.get("algorithm").and_then(Value::as_str) != Some("sha256")
    {
        return Err(format!("{STAMP_PATH} has an unsupported format"));
    }
    let web = crate_dir.join("web");
    validate_stamp_side(object, "input", &web, &input_files(&web)?)?;
    validate_stamp_side(
        object,
        "output",
        &web.join("dist"),
        &output_files(&web.join("dist"))?,
    )
}

fn validate_stamp_side(
    stamp: &Map<String, Value>,
    side: &str,
    root: &Path,
    files: &[String],
) -> Result<(), String> {
    let files_field = format!("{side}Files");
    let digest_field = format!("{side}Digest");
    if string_array(stamp, &files_field)? != files {
        return Err(format!("build stamp {files_field} is stale"));
    }
    if crate::required_string(stamp, &digest_field, "build stamp")? != digest_files(root, files)? {
        return Err(format!("build stamp {digest_field} is stale"));
    }
    Ok(())
}

fn output_files(dist: &Path) -> Result<Vec<String>, String> {
    collect_files(dist, &[], OUTPUT_IGNORED_FILES)
}

pub(super) fn collect_files(
    root: &Path,
    ignored_top_dirs: &[&str],
    ignored_files: &[&str],
) -> Result<Vec<String>, String> {
    fn visit(
        root: &Path,
        dir: &Path,
        ignored_top_dirs: &[&str],
        ignored_files: &[&str],
        files: &mut Vec<String>,
    ) -> Result<(), String> {
        for entry in fs::read_dir(dir)
            .map_err(|error| format!("could not read {}: {error}", dir.display()))?
        {
            let entry = entry
                .map_err(|error| format!("could not read {} entry: {error}", dir.display()))?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)
                .map_err(|error| format!("could not inspect {}: {error}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "frontend path must not be a symlink: {}",
                    path.display()
                ));
            }
            let relative = normalized_relative(root, &path)?;
            if metadata.is_dir() {
                if !relative.contains('/') && ignored_top_dirs.contains(&relative.as_str()) {
                    continue;
                }
                visit(root, &path, ignored_top_dirs, ignored_files, files)?;
            } else if metadata.is_file() {
                if !ignored_files.contains(&relative.as_str()) {
                    files.push(relative);
                }
            } else {
                return Err(format!("frontend path must be regular: {}", path.display()));
            }
        }
        Ok(())
    }
    let mut files = Vec::new();
    visit(root, root, ignored_top_dirs, ignored_files, &mut files)?;
    files.sort();
    Ok(files)
}

fn normalized_relative(root: &Path, path: &Path) -> Result<String, String> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| format!("{} is outside {}", path.display(), root.display()))?;
    relative
        .components()
        .map(|component| match component {
            Component::Normal(segment) => segment
                .to_str()
                .map(str::to_owned)
                .ok_or_else(|| format!("non-UTF-8 path: {}", path.display())),
            _ => Err(format!("unsafe path: {}", path.display())),
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|segments| segments.join("/"))
}

fn digest_files(root: &Path, files: &[String]) -> Result<String, String> {
    let mut digest = Sha256::new();
    for relative in files {
        validate_relative_path(relative, "digest file")?;
        let bytes = read_regular_file(&root.join(relative), "digest input")?;
        digest.update(relative.as_bytes());
        digest.update([0]);
        digest.update((bytes.len() as u64).to_be_bytes());
        digest.update(bytes);
    }
    let mut encoded = String::with_capacity(64);
    for byte in digest.finalize() {
        write!(&mut encoded, "{byte:02x}").expect("writing to a String cannot fail");
    }
    Ok(encoded)
}
