//! The appliance's login password verb (TUI rework §7): `login-password`
//! sets the password of the account that ran sudo. The new password comes
//! on standard input only: never in an argument, so sudo's journal line is
//! just `login-password`, and never in a file. `chpasswd` takes it on its
//! own standard input.

use std::io::Read;

use platform_host::{
    runner::{
        Program::{Chpasswd, Getent},
        Runner,
    },
    shell::valid_user,
};
use zeroize::Zeroizing;

use super::net::tail;

/// Shortest and longest new password.
pub const MIN: usize = 10;
pub const MAX: usize = 128;

/// Why `password` will not do, in the words the screen shows.
pub fn check(password: &str) -> Result<(), String> {
    let n = password.chars().count();
    if n < MIN {
        return Err(format!("At least {MIN} characters."));
    }
    if n > MAX {
        return Err(format!("At most {MAX} characters."));
    }
    if password.chars().any(char::is_control) {
        return Err("No control characters.".into());
    }
    Ok(())
}

/// The new password from standard input (one trailing newline removed).
pub(crate) fn read_password(input: &mut impl Read) -> Result<Zeroizing<String>, String> {
    let mut bytes = Zeroizing::new(Vec::new());
    input
        .take(1024)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("reading standard input: {error}"))?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "the password is not UTF-8".to_owned())?;
    Ok(Zeroizing::new(
        text.strip_suffix('\n').unwrap_or(text).to_owned(),
    ))
}

/// `login-password`: `user` is the person sudo names; prints `done<TAB>changed`.
pub(crate) fn run_password<R: Runner>(
    runner: &R,
    user: Option<&str>,
    password: &str,
) -> Result<String, String> {
    let user = user
        .filter(|u| valid_user(u))
        .ok_or("cannot tell whose password to change: run it through sudo as that account")?;
    check(password)?;
    // A real person's account, not a service's: the passwd entry says so.
    let entry = runner
        .run(Getent, &["passwd", user])
        .map_err(|error| format!("{}: {error}", Getent.path()))?;
    let uid = (entry.status == 0)
        .then(|| {
            entry
                .stdout
                .split(':')
                .nth(2)
                .and_then(|u| u.trim().parse::<u32>().ok())
        })
        .flatten()
        .ok_or_else(|| format!("{user} is not an account on this host"))?;
    if uid < 1000 {
        return Err(format!("{user} is a system account"));
    }
    let line = Zeroizing::new(format!("{user}:{password}\n"));
    let out = runner
        .run_with_input(Chpasswd, &[], line.as_bytes())
        .map_err(|error| format!("{}: {error}", Chpasswd.path()))?;
    if out.status != 0 {
        // chpasswd names the rule that failed; it never echoes the password.
        return Err(format!("chpasswd: {}", tail(&out.stderr)));
    }
    Ok("done\tchanged".into())
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
