use std::{
    collections::BTreeSet,
    env,
    fmt::Write,
    fs,
    path::{Component, Path, PathBuf},
};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

const DIST_DIR: &str = "web/dist";
const MANIFEST_PATH: &str = "web/dist/.vite/manifest.json";
const CONTRACT_PATH: &str = "web/frontend-contract.json";
const STAMP_PATH: &str = "web/dist/build-stamp.json";
const INPUT_IGNORED_DIRECTORIES: &[&str] = &[
    "coverage",
    "dist",
    "node_modules",
    "playwright-report",
    "test-results",
];
const OUTPUT_IGNORED_FILES: &[&str] = &[".gitkeep", "build-stamp.json"];
const RESERVED_PREFIXES: &[&str] = &["/api", "/auth", "/assets", "/health", "/ready"];

#[derive(Debug)]
struct FrontendContract {
    browser_routes: Vec<String>,
    public_assets: Vec<(String, String)>,
}

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_EMBEDDED_UI");
    println!("cargo:rerun-if-changed={CONTRACT_PATH}");
    let crate_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let contract = load_contract(&crate_dir)
        .unwrap_or_else(|error| panic!("frontend contract validation failed: {error}"));
    write_generated_contract(&contract)
        .unwrap_or_else(|error| panic!("frontend contract generation failed: {error}"));

    if env::var_os("CARGO_FEATURE_EMBEDDED_UI").is_none() {
        return;
    }
    println!("cargo:rerun-if-changed=web/dist");
    for file in input_files(&crate_dir.join("web"))
        .unwrap_or_else(|error| panic!("frontend input discovery failed: {error}"))
    {
        println!("cargo:rerun-if-changed=web/{file}");
    }
    validate_frontend(&crate_dir, &contract).unwrap_or_else(|error| {
        panic!(
            "embedded-ui frontend validation failed: {error}. The embedded-ui feature \
             (included by --all-features) needs a current frontend build: run \
             scripts/build-console.sh first"
        )
    });
}

fn load_contract(crate_dir: &Path) -> Result<FrontendContract, String> {
    let bytes = read_regular_nonempty(&crate_dir.join(CONTRACT_PATH), "frontend contract")?;
    let value: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("{CONTRACT_PATH} is not valid JSON: {error}"))?;
    let object = value
        .as_object()
        .ok_or_else(|| format!("{CONTRACT_PATH} must be an object"))?;
    let actual_keys = object.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if actual_keys != BTreeSet::from(["browserRoutes", "publicAssets"]) {
        return Err(format!("{CONTRACT_PATH} has unknown or missing keys"));
    }
    let browser_routes = string_array(object, "browserRoutes")?;
    let values = object
        .get("publicAssets")
        .and_then(Value::as_array)
        .ok_or_else(|| "publicAssets must be an array".to_owned())?;
    let mut public_assets = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let asset = value
            .as_object()
            .ok_or_else(|| format!("publicAssets[{index}] must be an object"))?;
        if asset.keys().map(String::as_str).collect::<BTreeSet<_>>()
            != BTreeSet::from(["file", "route"])
        {
            return Err(format!("publicAssets[{index}] has unknown or missing keys"));
        }
        public_assets.push((
            required_string(asset, "route", "public asset")?.to_owned(),
            required_string(asset, "file", "public asset")?.to_owned(),
        ));
    }
    let contract = FrontendContract {
        browser_routes,
        public_assets,
    };
    validate_contract(crate_dir, &contract)?;
    Ok(contract)
}

fn validate_contract(crate_dir: &Path, contract: &FrontendContract) -> Result<(), String> {
    if contract.browser_routes.first().map(String::as_str) != Some("/") {
        return Err("browserRoutes must begin with /".to_owned());
    }
    let mut browser_routes = BTreeSet::new();
    for route in &contract.browser_routes {
        validate_route(route, "browser")?;
        if is_reserved_route(route) || !browser_routes.insert(route.as_str()) {
            return Err(format!(
                "browser route is reserved or duplicated: {route:?}"
            ));
        }
    }
    let mut public_routes = BTreeSet::new();
    let mut public_files = BTreeSet::new();
    for (route, file) in &contract.public_assets {
        validate_route(route, "public asset")?;
        validate_relative_path(file, "public asset file")?;
        if is_reserved_route(route)
            || browser_routes.contains(route.as_str())
            || !public_routes.insert(route.as_str())
            || !public_files.insert(file.as_str())
        {
            return Err(format!(
                "public asset is reserved, colliding, or duplicated: {route:?} -> {file:?}"
            ));
        }
    }
    let discovered = collect_files(&crate_dir.join("web/public"), &[], &[])?
        .into_iter()
        .collect::<BTreeSet<_>>();
    let declared = contract
        .public_assets
        .iter()
        .map(|(_, file)| file.clone())
        .collect::<BTreeSet<_>>();
    if discovered != declared {
        return Err(format!(
            "public asset inventory mismatch; declared={declared:?}, discovered={discovered:?}"
        ));
    }
    Ok(())
}

fn write_generated_contract(contract: &FrontendContract) -> Result<(), String> {
    let out_dir =
        PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| "OUT_DIR is not set".to_owned())?);
    let mut generated = String::from(
        "// Generated from web/frontend-contract.json.\npub(crate) const BROWSER_ROUTES: &[&str] = &[\n",
    );
    for route in &contract.browser_routes {
        generated.push_str(&format!("    {route:?},\n"));
    }
    generated.push_str("];\npub(crate) const PUBLIC_ASSETS: &[(&str, &str)] = &[\n");
    for (route, file) in &contract.public_assets {
        generated.push_str(&format!("    ({route:?}, {file:?}),\n"));
    }
    generated.push_str("];\n");
    fs::write(out_dir.join("frontend_contract.rs"), generated)
        .map_err(|error| format!("could not write generated frontend contract: {error}"))
}

fn validate_frontend(crate_dir: &Path, contract: &FrontendContract) -> Result<(), String> {
    let dist = crate_dir.join(DIST_DIR);
    let index = read_regular_nonempty(&dist.join("index.html"), "entry document")?;
    let manifest_bytes = read_regular_nonempty(&crate_dir.join(MANIFEST_PATH), "Vite manifest")?;
    let manifest: Value = serde_json::from_slice(&manifest_bytes)
        .map_err(|error| format!("{MANIFEST_PATH} is not valid JSON: {error}"))?;
    let entries = manifest
        .as_object()
        .filter(|entries| !entries.is_empty())
        .ok_or_else(|| format!("{MANIFEST_PATH} must be a non-empty object"))?;
    let index_entry = entries
        .get("index.html")
        .and_then(Value::as_object)
        .ok_or_else(|| format!("{MANIFEST_PATH} has no index.html entry"))?;
    if index_entry.get("isEntry") != Some(&Value::Bool(true)) {
        return Err("index.html must be marked as an entry".to_owned());
    }
    for (entry_name, entry) in entries {
        validate_entry_files(
            &dist,
            entry_name,
            entry
                .as_object()
                .ok_or_else(|| format!("manifest entry {entry_name:?} is not an object"))?,
        )?;
    }
    let index_text =
        std::str::from_utf8(&index).map_err(|error| format!("index.html is not UTF-8: {error}"))?;
    for (route, relative) in &contract.public_assets {
        let generated = read_generated_file(&dist, relative, route)?;
        let source = read_regular_nonempty(
            &crate_dir.join("web/public").join(relative),
            "public source asset",
        )?;
        if generated != source {
            return Err(format!(
                "generated public asset {relative:?} differs from source"
            ));
        }
    }
    let entry_file = required_path(index_entry, "file", "index.html")?;
    if !index_text.contains(&format!("/{entry_file}")) {
        return Err(format!("index.html does not reference {entry_file:?}"));
    }
    for css in path_array(index_entry, "css", "index.html")? {
        if !index_text.contains(&format!("/{css}")) {
            return Err(format!("index.html does not reference {css:?}"));
        }
    }
    validate_build_stamp(crate_dir)
}

fn validate_build_stamp(crate_dir: &Path) -> Result<(), String> {
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
    if required_string(stamp, &digest_field, "build stamp")? != digest_files(root, files)? {
        return Err(format!("build stamp {digest_field} is stale"));
    }
    Ok(())
}

fn input_files(web: &Path) -> Result<Vec<String>, String> {
    collect_files(web, INPUT_IGNORED_DIRECTORIES, &[])
}
fn output_files(dist: &Path) -> Result<Vec<String>, String> {
    collect_files(dist, &[], OUTPUT_IGNORED_FILES)
}

fn collect_files(
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

fn validate_entry_files(
    dist: &Path,
    entry_name: &str,
    entry: &Map<String, Value>,
) -> Result<(), String> {
    validate_manifest_asset(dist, required_path(entry, "file", entry_name)?, entry_name)?;
    for field in ["css", "assets"] {
        for path in path_array(entry, field, entry_name)? {
            validate_manifest_asset(dist, path, entry_name)?;
        }
    }
    Ok(())
}

fn validate_manifest_asset(dist: &Path, relative: &str, entry_name: &str) -> Result<(), String> {
    validate_relative_path(relative, "manifest asset")?;
    if !relative.starts_with("assets/") || !has_content_hash(relative) {
        return Err(format!(
            "manifest entry {entry_name:?} references non-hashed or unreserved asset {relative:?}"
        ));
    }
    read_generated_file(dist, relative, entry_name).map(|_| ())
}

fn has_content_hash(relative: &str) -> bool {
    let Some((stem, _)) = relative
        .rsplit('/')
        .next()
        .and_then(|name| name.rsplit_once('.'))
    else {
        return false;
    };
    stem.match_indices('-').any(|(index, _)| {
        let candidate = &stem[index + 1..];
        candidate.len() >= 8
            && candidate
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    })
}

fn validate_route(route: &str, description: &str) -> Result<(), String> {
    if (route != "/" && route.ends_with('/'))
        || !route.starts_with('/')
        || route.contains("//")
        || route.contains(['?', '#', '\\', '%'])
        || route.chars().any(char::is_control)
        || (route != "/"
            && route
                .split('/')
                .skip(1)
                .any(|segment| segment.is_empty() || segment == "." || segment == ".."))
    {
        return Err(format!("{description} route is not canonical: {route:?}"));
    }
    Ok(())
}

fn is_reserved_route(route: &str) -> bool {
    RESERVED_PREFIXES
        .iter()
        .any(|prefix| route == *prefix || route.starts_with(&format!("{prefix}/")))
}

fn validate_relative_path(path: &str, description: &str) -> Result<(), String> {
    let value = Path::new(path);
    if path.is_empty()
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || value.is_absolute()
        || value
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(format!("{description} contains unsafe path {path:?}"));
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    description: &str,
) -> Result<&'a str, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{description} has no non-empty {field:?}"))
}
fn required_path<'a>(
    entry: &'a Map<String, Value>,
    field: &str,
    name: &str,
) -> Result<&'a str, String> {
    required_string(entry, field, &format!("manifest entry {name:?}"))
}
fn string_array(object: &Map<String, Value>, field: &str) -> Result<Vec<String>, String> {
    object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{field:?} must be an array"))?
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_str()
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("{field:?}[{index}] must be a non-empty string"))
        })
        .collect()
}
fn path_array<'a>(
    entry: &'a Map<String, Value>,
    field: &str,
    name: &str,
) -> Result<Vec<&'a str>, String> {
    let Some(value) = entry.get(field) else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .ok_or_else(|| format!("manifest entry {name:?} field {field:?} is not an array"))?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|path| !path.is_empty())
                .ok_or_else(|| format!("manifest entry {name:?} field {field:?} has invalid path"))
        })
        .collect()
}
fn read_generated_file(dist: &Path, relative: &str, name: &str) -> Result<Vec<u8>, String> {
    validate_relative_path(relative, "generated frontend file")?;
    read_regular_nonempty(&dist.join(relative), "generated frontend asset")
        .map_err(|error| format!("frontend entry {name:?} references {relative:?}: {error}"))
}
fn read_regular_nonempty(path: &Path, description: &str) -> Result<Vec<u8>, String> {
    let bytes = read_regular_file(path, description)?;
    if bytes.is_empty() {
        return Err(format!("{description} {} is empty", path.display()));
    }
    Ok(bytes)
}
fn read_regular_file(path: &Path, description: &str) -> Result<Vec<u8>, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("missing {description} {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{description} {} is not a regular file",
            path.display()
        ));
    }
    fs::read(path)
        .map_err(|error| format!("could not read {description} {}: {error}", path.display()))
}
