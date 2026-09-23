use std::{
    env, fs,
    path::{Component, Path, PathBuf},
};

use serde_json::{Map, Value};

mod public_assets {
    include!("src/public_assets.rs");
}

const DIST_DIR: &str = "web/dist";
const MANIFEST_PATH: &str = "web/dist/.vite/manifest.json";

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EMBEDDED_UI");
    println!("cargo:rerun-if-changed=src/public_assets.rs");
    if env::var_os("CARGO_FEATURE_EMBEDDED_UI").is_none() {
        return;
    }

    println!("cargo:rerun-if-changed={DIST_DIR}");
    if let Err(error) = validate_frontend() {
        panic!("embedded-ui frontend validation failed: {error}");
    }
}

fn validate_frontend() -> Result<(), String> {
    let crate_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR")
            .ok_or_else(|| "CARGO_MANIFEST_DIR is not set".to_owned())?,
    );
    let dist = crate_dir.join(DIST_DIR);
    let index = read_nonempty(&dist.join("index.html"), "entry document")?;
    let manifest_bytes = read_nonempty(&crate_dir.join(MANIFEST_PATH), "Vite manifest")?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("{MANIFEST_PATH} is not valid JSON: {error}"))?;
    let entries = manifest
        .as_object()
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| format!("{MANIFEST_PATH} must be a non-empty JSON object"))?;

    let index_entry = entries
        .get("index.html")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{MANIFEST_PATH} has no index.html entry"))?;
    if index_entry.get("isEntry") != Some(&Value::Bool(true)) {
        return Err(format!(
            "{MANIFEST_PATH} index.html must be marked as an entry"
        ));
    }

    for (entry_name, entry) in entries {
        let entry = entry
            .as_object()
            .ok_or_else(|| format!("manifest entry {entry_name:?} is not an object"))?;
        validate_entry_files(&dist, entry_name, entry)?;
    }

    for (route, relative) in public_assets::PUBLIC_ASSETS {
        if !route.starts_with('/') || route.ends_with('/') {
            return Err(format!("public asset route {route:?} is not canonical"));
        }
        validate_generated_file(&dist, relative, route)?;
        if !index_text_contains(&index, route)? {
            return Err(format!(
                "web/dist/index.html does not reference public asset route {route:?}"
            ));
        }
    }

    let index_text = std::str::from_utf8(&index)
        .map_err(|error| format!("web/dist/index.html is not UTF-8: {error}"))?;
    let entry_file = required_path(index_entry, "file", "index.html")?;
    if !index_text.contains(&format!("/{entry_file}")) {
        return Err(format!(
            "web/dist/index.html does not reference manifest entry file {entry_file:?}"
        ));
    }
    for css in path_array(index_entry, "css", "index.html")? {
        if !index_text.contains(&format!("/{css}")) {
            return Err(format!(
                "web/dist/index.html does not reference manifest stylesheet {css:?}"
            ));
        }
    }

    Ok(())
}

fn index_text_contains(index: &[u8], route: &str) -> Result<bool, String> {
    let index = std::str::from_utf8(index)
        .map_err(|error| format!("web/dist/index.html is not UTF-8: {error}"))?;
    Ok(index.contains(route))
}

fn validate_entry_files(
    dist: &Path,
    entry_name: &str,
    entry: &Map<String, Value>,
) -> Result<(), String> {
    let file = required_path(entry, "file", entry_name)?;
    validate_generated_file(dist, file, entry_name)?;
    for field in ["css", "assets"] {
        for path in path_array(entry, field, entry_name)? {
            validate_generated_file(dist, path, entry_name)?;
        }
    }
    Ok(())
}

fn required_path<'a>(
    entry: &'a Map<String, Value>,
    field: &str,
    entry_name: &str,
) -> Result<&'a str, String> {
    entry
        .get(field)
        .and_then(Value::as_str)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| format!("manifest entry {entry_name:?} has no non-empty {field:?}"))
}

fn path_array<'a>(
    entry: &'a Map<String, Value>,
    field: &str,
    entry_name: &str,
) -> Result<Vec<&'a str>, String> {
    let Some(value) = entry.get(field) else {
        return Ok(Vec::new());
    };
    let values = value
        .as_array()
        .ok_or_else(|| format!("manifest entry {entry_name:?} field {field:?} is not an array"))?;
    values
        .iter()
        .map(|value| {
            value.as_str().filter(|path| !path.is_empty()).ok_or_else(|| {
                format!(
                    "manifest entry {entry_name:?} field {field:?} contains a non-string or empty path"
                )
            })
        })
        .collect()
}

fn validate_generated_file(dist: &Path, relative: &str, entry_name: &str) -> Result<(), String> {
    let path = Path::new(relative);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!(
            "manifest entry {entry_name:?} contains unsafe path {relative:?}"
        ));
    }
    if !relative.starts_with("assets/") && !entry_name.starts_with('/') {
        return Err(format!(
            "manifest entry {entry_name:?} references {relative:?} outside the reserved assets directory"
        ));
    }
    read_nonempty(&dist.join(path), "manifest-referenced asset").map(|_| ())
}

fn read_nonempty(path: &Path, description: &str) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "missing or unreadable {description} {}: {error}; run the Vite production build first",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        return Err(format!("{description} {} is empty", path.display()));
    }
    Ok(bytes)
}
