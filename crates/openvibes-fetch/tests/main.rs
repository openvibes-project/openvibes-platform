//! The binary itself: a client that hangs up before the answer.
// Runs the binary under test (a fixed path from Cargo), never a shell.
#![allow(clippy::disallowed_types)]

use std::{
    io::Write,
    process::{Command, Stdio},
};

#[test]
fn a_closed_stdout_is_no_panic() {
    let dir = std::env::temp_dir().join(format!("ov-fetch-main-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("fetch.toml");
    std::fs::write(
        &config,
        "database_url = \"postgresql:///x?host=/nonexistent\"\n",
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_openvibes-fetch"))
        .arg("--config")
        .arg(&config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The client is gone before the answer: the write fails with EPIPE.
    drop(child.stdout.take());
    child.stdin.take().unwrap().write_all(b"not json").unwrap();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{:?} {stderr}", out.status);
    assert!(!stderr.contains("panicked"), "{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}
