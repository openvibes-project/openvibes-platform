//! `openvibes-admin rules publish-site`: the site's own rules, signed by
//! the rule signer (board #107) after it checks the user's password itself,
//! then published like any envelope. A scripting path beside the console;
//! the signer, not this command, is the security boundary.

use std::{
    io::{BufRead, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::Duration,
};

use zeroize::Zeroizing;

/// The signer's socket (packaging).
pub const SOCKET: &str = "/run/openvibes-signer/sign.sock";
/// Largest rule set sent (the signer's request limit, less the envelope).
const MAX_RULES: u64 = 900 * 1024;

/// What a refusal code means, for the operator.
fn refusal(code: &str) -> String {
    match code {
        "credentials" => "wrong username or password".into(),
        "throttled" => "the account is locked after wrong passwords; try again in 15 minutes".into(),
        "forbidden" => "the account may not publish rules (rules.upload), or must change its password first".into(),
        "limits" => "over a limit: too many rules, or an alarm rule naming more than 8 programs (32 per set)".into(),
        "invalid" => "not a valid site rule set (site: findings rules only; site-alarms: alarm rules with programs)".into(),
        "rate" => "the hourly publish limit is reached; try again later".into(),
        "version_state" => "the signer has no version state: run Setup's Repair".into(),
        "unavailable" => "the signer cannot reach its database or state; see journalctl -u openvibes-signer".into(),
        other => format!("refused ({other})"),
    }
}

/// The request bytes, serialized straight into a zeroized buffer (no copy
/// of the password lingers in a JSON value), within the signer's limit:
/// the rules travel as an escaped JSON string, so a file under the limit
/// can still come out over it, and the signer would answer `invalid`.
fn request(
    user: &str,
    password: &str,
    rule_set: &str,
    rules: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    #[derive(serde::Serialize)]
    struct Request<'a> {
        username: &'a str,
        password: &'a str,
        rule_set: &'a str,
        rules: &'a str,
    }
    let request = Zeroizing::new(
        serde_json::to_vec(&Request {
            username: user,
            password,
            rule_set,
            rules,
        })
        .map_err(|error| error.to_string())?,
    );
    if request.len() as u64 > openvibes_signer::MAX_REQUEST {
        return Err(format!(
            "too large: the request to the signer must stay under {} bytes (quotes in the rules count twice)",
            openvibes_signer::MAX_REQUEST
        ));
    }
    Ok(request)
}

/// Asks the signer to sign `rules_file` as `rule_set` for `user`, whose
/// password is read from the terminal. Returns the envelope bytes.
pub fn sign(
    socket: &Path,
    user: &str,
    rule_set: &str,
    rules_file: &Path,
    password_stdin: bool,
) -> Result<Vec<u8>, String> {
    if rule_set != "site" && rule_set != "site-alarms" {
        return Err("--set must be site or site-alarms".into());
    }
    let mut rules = String::new();
    std::fs::File::open(rules_file)
        .and_then(|file| file.take(MAX_RULES + 1).read_to_string(&mut rules))
        .map_err(|error| format!("{}: {error}", rules_file.display()))?;
    if rules.len() as u64 > MAX_RULES {
        return Err(format!(
            "{} is larger than {MAX_RULES} bytes",
            rules_file.display()
        ));
    }
    let password = if password_stdin {
        let mut line = Zeroizing::new(String::new());
        std::io::stdin()
            .lock()
            .take(4096)
            .read_line(&mut line)
            .map_err(|_| "cannot read the password from stdin".to_owned())?;
        Zeroizing::new(line.trim_end_matches(['\r', '\n']).to_owned())
    } else {
        rpassword::prompt_password(format!("Password for {user}: "))
            .map(Zeroizing::new)
            .map_err(|_| {
                "password input requires an interactive terminal (or --password-stdin)".to_owned()
            })?
    };
    let request = request(user, &password, rule_set, &rules)
        .map_err(|error| format!("{}: {error}", rules_file.display()))?;
    let mut stream = UnixStream::connect(socket).map_err(|error| {
        format!(
            "cannot reach the rule signer at {}: {error}",
            socket.display()
        )
    })?;
    // Argon2 and a busy signer take a moment; never hang a script.
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .and_then(|()| stream.set_write_timeout(Some(Duration::from_secs(30))))
        .map_err(|error| error.to_string())?;
    stream
        .write_all(&request)
        .map_err(|error| error.to_string())?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .map_err(|error| error.to_string())?;
    let mut answer = Vec::new();
    stream
        .take(4 << 20)
        .read_to_end(&mut answer)
        .map_err(|error| format!("no answer from the rule signer: {error}"))?;
    let answer: serde_json::Value =
        serde_json::from_slice(&answer).map_err(|_| "the rule signer gave no answer".to_owned())?;
    match answer["result"].as_str() {
        Some("signed") => answer["envelope"]
            .as_str()
            .map(|envelope| envelope.as_bytes().to_vec())
            .ok_or_else(|| "the rule signer's answer has no envelope".to_owned()),
        _ => Err(refusal(answer["code"].as_str().unwrap_or("unknown"))),
    }
}

#[cfg(test)]
mod tests {
    /// A rule file under the read limit whose quotes push the escaped
    /// request over the signer's limit is "too large", not sent.
    #[test]
    fn escaping_counts_against_the_signers_limit() {
        let quotes = "\"".repeat(600 * 1024);
        let error = super::request("u", "p", "site", &quotes).unwrap_err();
        assert!(error.starts_with("too large"), "{error}");
        let fits = super::request("u", "p", "site", "{}").unwrap();
        let value: serde_json::Value = serde_json::from_slice(&fits).unwrap();
        assert_eq!(value["password"], "p");
        assert_eq!(value["rules"], "{}");
    }
}
