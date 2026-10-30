//! `helper admin-reset`: a new one-time password for the console's `admin`
//! (2b-2, Console sign-in). Break-glass: the CLI also unlocks and enables
//! the account. The password goes to the CLI on stdin and back to the TUI
//! on stdout, never into an argument, the journal or a file.

use std::process::ExitCode;

use platform_host::{StepState, runner::Runner};
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::Zeroizing;

use super::Ctx;

/// No 0/O/1/l/I: read off a screen (ruling 3).
const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";

/// `Tz4m-W8qH-n2cR-7kLp`: 4 groups of 4 from `ALPHABET`, uniformly.
pub fn readable_password() -> Result<Zeroizing<String>, String> {
    // The largest multiple of the alphabet's size below 256: rejecting the
    // bytes above it keeps every character equally likely.
    let limit = 256 - 256 % ALPHABET.len();
    let mut password = Zeroizing::new(String::with_capacity(19));
    let mut bytes = Zeroizing::new([0_u8; 32]);
    let mut taken = 0;
    while taken < 16 {
        SystemRandom::new()
            .fill(&mut *bytes)
            .map_err(|_| "could not generate a password".to_owned())?;
        for &byte in bytes.iter().filter(|&&b| usize::from(b) < limit) {
            if taken == 16 {
                break;
            }
            if taken > 0 && taken % 4 == 0 {
                password.push('-');
            }
            password.push(char::from(ALPHABET[usize::from(byte) % ALPHABET.len()]));
            taken += 1;
        }
    }
    Ok(password)
}

/// Resets `admin` through the CLI; `Done(password)` for the TUI to show once.
pub fn admin_reset<R: Runner>(ctx: &Ctx<R>) -> Result<StepState, String> {
    let password = readable_password()?;
    let input = Zeroizing::new(format!("{}\n", *password));
    ctx.as_admin_with_input(
        &[
            "user",
            "reset-password",
            "admin",
            "--password-stdin",
            "--must-change",
            "--recover",
        ],
        input.as_bytes(),
    )
    .map_err(|error| reason(&error))?;
    Ok(StepState::Done(password.to_string()))
}

/// The CLI's own words, short enough for the page: without the command line
/// (`/usr/sbin/runuser … --must-change: `) and the `openvibes-admin: `
/// prefix; a database problem says what to do.
pub(super) fn reason(error: &str) -> String {
    let why = match error.rsplit_once("openvibes-admin: ") {
        Some((_, why)) => why,
        None => error.split_once(": ").map_or(error, |(_, why)| why),
    }
    .trim();
    if why == "no local user named admin" {
        return "There is no local account named admin.".into();
    }
    let mut chars = why.chars();
    let why: String = chars
        .next()
        .map(|c| c.to_uppercase().chain(chars).collect())
        .unwrap_or_default();
    if why.starts_with("Database") || why.starts_with("Schema") || why.contains("database_url") {
        format!("{}. Repair first.", why.trim_end_matches('.'))
    } else {
        why
    }
}

/// `helper admin-reset`: prints `done<TAB>PASSWORD` or `failed<TAB>WHY`.
pub fn run() -> ExitCode {
    let (_lock, plan) = match super::begin() {
        Ok(v) => v,
        Err(code) => return code,
    };
    let state = admin_reset(&super::host_ctx(&plan, false)).unwrap_or_else(StepState::Failed);
    println!("{}", state.line());
    ExitCode::SUCCESS
}

#[cfg(test)]
#[path = "admin_reset_tests.rs"]
mod tests;
