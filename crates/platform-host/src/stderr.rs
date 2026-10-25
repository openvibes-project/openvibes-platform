//! A failed command's standard error, made fit for a screen.

/// Error text for a screen: trimmed, control characters escaped.
pub(crate) fn printable(text: &str) -> String {
    text.trim()
        .chars()
        .map(|c| {
            if c.is_control() && c != '\n' {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// `stderr` without sudo's first-use lecture, which comes before whatever
/// went wrong and so stood in for it (board #75): from its first line
/// through "#3)", and the "password … will not be visible" note after it.
pub(crate) fn without_lecture(stderr: &str) -> String {
    let Some(start) = stderr.find("We trust you have received the usual lecture") else {
        return stderr.to_owned();
    };
    let rest = &stderr[start..];
    let end = rest
        .find("#3)")
        .and_then(|at| rest[at..].find('\n').map(|nl| at + nl + 1))
        .unwrap_or(rest.len());
    let mut after = &rest[end..];
    let note = "For security reasons, the password you type will not be visible.";
    if let Some(stripped) = after.trim_start().strip_prefix(note) {
        after = stripped;
    }
    format!("{}{}", &stderr[..start], after).trim().to_owned()
}
