//! How people may sign in over SSH (System › SSH): keys, passwords or both,
//! as a drop-in for `sshd`. What is chosen is checked here before it reaches
//! a file.

/// Where the helper writes the choice (an `Include` drop-in of
/// `sshd_config`).
pub const DROP_IN: &str = "etc/ssh/sshd_config.d/50-openvibes.conf";

/// What the host allows now.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SshInfo {
    /// Public key sign-in is allowed.
    pub keys: bool,
    /// Password sign-in is allowed.
    pub passwords: bool,
    /// The signed-in account has at least one authorized key; `None`: not
    /// known.
    pub has_keys: Option<bool>,
}

impl Default for SshInfo {
    /// What `sshd` does with no drop-in.
    fn default() -> Self {
        SshInfo {
            keys: true,
            passwords: true,
            has_keys: None,
        }
    }
}

/// `Allow keys` and `Allow passwords`: at least one must stay on, or nobody
/// could sign in again.
pub fn check(keys: bool, passwords: bool) -> Result<(), String> {
    if keys || passwords {
        Ok(())
    } else {
        Err("Keys and passwords cannot both be off: nobody could sign in.".into())
    }
}

fn word(on: bool) -> &'static str {
    if on { "yes" } else { "no" }
}

/// The drop-in the helper writes.
#[must_use]
pub fn drop_in(keys: bool, passwords: bool) -> String {
    format!(
        "# Written by OpenVIBES (System > SSH). Do not edit.\nPubkeyAuthentication {}\nPasswordAuthentication {}\n",
        word(keys),
        word(passwords)
    )
}

/// `yes` or `no`, as the helper takes it.
pub fn parse_word(text: &str) -> Result<bool, String> {
    match text {
        "yes" => Ok(true),
        "no" => Ok(false),
        other => Err(format!("{other} is not yes or no")),
    }
}

/// The choice a drop-in written by [`drop_in`] holds.
#[must_use]
pub fn read_drop_in(text: &str) -> Option<(bool, bool)> {
    let value = |name: &str| {
        text.lines().find_map(|line| {
            let mut words = line.split_whitespace();
            (words.next() == Some(name))
                .then(|| words.next().and_then(|w| parse_word(w).ok()))
                .flatten()
        })
    };
    Some((
        value("PubkeyAuthentication")?,
        value("PasswordAuthentication")?,
    ))
}

/// What System shows for the page.
#[must_use]
pub fn menu_line(info: &SshInfo) -> String {
    match (info.keys, info.passwords) {
        (true, true) => "keys and passwords",
        (true, false) => "keys only",
        (false, true) => "passwords only",
        (false, false) => "nobody can sign in",
    }
    .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn at_least_one_way_in_stays() {
        assert!(check(true, true).is_ok());
        assert!(check(true, false).is_ok());
        assert!(check(false, true).is_ok());
        assert!(check(false, false).is_err());
    }

    #[test]
    fn the_drop_in_round_trips() {
        for (keys, passwords) in [(true, true), (true, false), (false, true)] {
            let text = drop_in(keys, passwords);
            assert_eq!(read_drop_in(&text), Some((keys, passwords)), "{text}");
        }
        assert_eq!(read_drop_in("PubkeyAuthentication yes\n"), None);
        assert!(parse_word("maybe").is_err());
    }

    #[test]
    fn the_menu_line_names_the_ways_in() {
        let mut info = SshInfo::default();
        assert_eq!(menu_line(&info), "keys and passwords");
        info.passwords = false;
        assert_eq!(menu_line(&info), "keys only");
    }
}
