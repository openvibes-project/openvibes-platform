# console-build-stamp

Build-script module that checks the web frontend's sorted source/output file
inventories and SHA-256 digests before `embedded-ui` is compiled.

## Interface

- `input_files(web)` returns normalized, sorted source paths, excluding build
  output, dependency, coverage, and browser-test directories.
- `validate_build_stamp(crate_dir)` checks the generated stamp's schema,
  inventory, and digest against the current files.
- File enumeration refuses symlinks, special files, and non-UTF-8 paths.

The module has no runtime configuration. Its ignore lists are build-script
constants. A stale, malformed, or unsafe inventory fails the Rust build with
the frontend build instruction from `build.rs`.

## How to check

Run `scripts/build-console.sh`, then
`cargo check --locked -p openvibes-console --features embedded-ui`. The build
script regenerates the stamp; the Cargo build verifies it before embedding.
