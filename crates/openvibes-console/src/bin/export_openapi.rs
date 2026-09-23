//! Emits or checks the generated console OpenAPI document.

use std::{env, fs, path::Path, process::ExitCode};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("export_openapi: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    let generated = openvibes_console::openapi_json()
        .map_err(|error| format!("could not serialize OpenAPI: {error}"))?;
    match arguments.as_slice() {
        [] => {
            print!("{generated}");
            Ok(())
        }
        [flag, path] if flag == "--check" => check(Path::new(path), &generated),
        _ => Err("usage: export_openapi [--check PATH]".to_owned()),
    }
}

fn check(path: &Path, generated: &str) -> Result<(), String> {
    let snapshot = fs::read_to_string(path)
        .map_err(|error| format!("could not read {}: {error}", path.display()))?;
    if snapshot == generated {
        Ok(())
    } else {
        Err(format!(
            "{} differs from the generated OpenAPI document",
            path.display()
        ))
    }
}
