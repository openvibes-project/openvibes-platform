#![forbid(unsafe_code)]

//! `openvibes-picture`: reads one request from stdin (see `wire`), writes one
//! response to stdout. Started by `openvibes-picture@.service`, which holds
//! the limits: no network, 256 MiB, 10 s of CPU, nothing writable.

use std::{
    io::{Read, Write},
    process::ExitCode,
};

use openvibes_picture::{Refusal, wire};

fn main() -> ExitCode {
    let mut request = Vec::new();
    let read = std::io::stdin()
        .take(wire::MAX_REQUEST as u64 + 1)
        .read_to_end(&mut request);
    let reply = if read.is_err() {
        return ExitCode::FAILURE;
    } else if request.len() > wire::MAX_REQUEST {
        wire::response(Err(Refusal::TooLarge))
    } else {
        wire::handle(&request)
    };
    match std::io::stdout().write_all(&reply) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::FAILURE,
    }
}
