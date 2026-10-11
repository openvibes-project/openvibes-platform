//! Journal lines made readable for the Service and Log screens.

/// A journal line (`short-iso`) as `HH:MM:SS LEVEL message key=value…`
/// (fields in key order) when the service logged tracing JSON (board #78: the raw JSON was hard
/// to read); any other line as it is.
pub fn readable(line: &str) -> String {
    let Some(start) = line.find(": {") else {
        return line.to_owned();
    };
    let Ok(serde_json::Value::Object(event)) = serde_json::from_str(&line[start + 2..]) else {
        return line.to_owned();
    };
    // `2026-09-30T17:02:10+02:00 host unit[pid]:` → the local time.
    let time = line
        .split_whitespace()
        .next()
        .and_then(|stamp| stamp.split_once('T'))
        .map_or("", |(_, rest)| rest.get(..8).unwrap_or(rest));
    // Decoding turns a JSON escape like `\u001b` back into a real control
    // character, which ratatui would write to the terminal (reviewer on
    // #112): escape every decoded piece again.
    let text = |value: &serde_json::Value| {
        let raw = match value {
            serde_json::Value::String(text) => text.clone(),
            other => other.to_string(),
        };
        safe(&raw)
    };
    let mut out = format!(
        "{time} {}",
        event.get("level").map(text).unwrap_or_default()
    );
    if let Some(serde_json::Value::Object(fields)) = event.get("fields") {
        if let Some(message) = fields.get("message") {
            out.push(' ');
            out.push_str(&text(message));
        }
        for (key, value) in fields.iter().filter(|(key, _)| *key != "message") {
            out.push_str(&format!(" {}={}", safe(key), text(value)));
        }
    }
    out
}

/// `text` with control characters escaped (`\u{1b}`), as the journal
/// reader does for the raw line.
fn safe(text: &str) -> String {
    text.chars()
        .map(|c| {
            if c.is_control() {
                c.escape_default().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::readable;

    /// Reviewer on #112: a log field can carry outside text; decoded, a
    /// JSON `\u001b` must not become a real escape sequence on screen.
    #[test]
    fn decoded_control_characters_stay_escaped() {
        let line = "2026-09-30T17:02:10+02:00 h openvibes-ingest[1]: \
                    {\"level\":\"WARN\",\"fields\":{\"message\":\"a\\u001b[31mb\",\
                    \"k\\u0007\":\"x\\u009b2J\"}}";
        let out = readable(line);
        assert!(!out.chars().any(char::is_control), "{out:?}");
        assert!(out.contains(r"a\u{1b}[31mb"), "{out:?}");
    }

    #[test]
    fn tracing_json_reads_as_one_short_line() {
        let line = "2026-09-30T17:02:10+02:00 metabox-lnx openvibes-ingest[3842528]: \
                    {\"timestamp\":\"2026-09-30T15:02:10.955489Z\",\"level\":\"INFO\",\
                    \"fields\":{\"message\":\"request\",\"endpoint\":\"/v1/heartbeat\",\
                    \"status\":204,\"latency_ms\":8},\"target\":\"platform_agent_server::limits\"}";
        assert_eq!(
            readable(line),
            "17:02:10 INFO request endpoint=/v1/heartbeat latency_ms=8 status=204"
        );
    }

    #[test]
    fn other_lines_are_left_alone() {
        for line in [
            "2026-09-30T17:02:10+02:00 metabox-lnx systemd[1]: Started openvibes-ingest.service.",
            "-- No entries --",
            "2026-09-30T17:02:10+02:00 h u[1]: {not json",
        ] {
            assert_eq!(readable(line), line);
        }
    }
}
