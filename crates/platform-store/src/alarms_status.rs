//! Threat alarms on one host (eBPF watcher, spec 2026-10-08 §5): on, and
//! from which source, or off with why and the one command that fixes it.
//! Derived from the stored `health.alarms` when read, never stored. Shared by
//! the console and the admin CLI, so both say the same words.

use openvibes_core::{AlarmHealth, AlarmSource, CollectorOutcome, FallbackDetail};

/// Sets the audit fallback up on the host (the agent package ships it).
pub const AUDIT_FALLBACK: &str = "sudo /usr/libexec/openvibes-agent/audit-fallback";
/// Restarts the agent, which reopens its process-start source.
pub const RESTART: &str = "sudo systemctl restart openvibes-agent";

/// Threat alarms on one host, from its last health report.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AlarmsStatus {
    /// Alarms are fed; `source` is `ebpf` or `audit`.
    On {
        /// `ebpf` or `audit`.
        source: &'static str,
    },
    /// Alarms are off.
    Off {
        /// `not_enabled`, `reader_failed`, `no_source` or `audit_not_set_up`.
        reason: &'static str,
        /// Why, in words.
        text: String,
        /// What turns them on, in words.
        fix: String,
        /// The command to run on the host for that, when there is one.
        command: Option<&'static str>,
        /// Off by a fault, not by the admin's choice (the Hosts list badges these).
        fault: bool,
    },
}

/// The status from a host's last report. `reported`: the host sent a health
/// report; `alarms`: its stored `health -> 'alarms'` (absent or JSON null when
/// process events are not enabled). `None` before a report, or when the stored
/// value does not parse.
///
/// The agent sets `source` and `fallback` once at start. Its `collector` is
/// `not_found` until the first program start and `ok` after it; anything else
/// means the reader is not working (it never opened, or it stopped).
#[must_use]
pub fn alarms_status(reported: bool, alarms: Option<&serde_json::Value>) -> Option<AlarmsStatus> {
    if !reported {
        return None;
    }
    let Some(value) = alarms.filter(|value| !value.is_null()) else {
        return Some(AlarmsStatus::Off {
            reason: "not_enabled",
            text: "process events are not enabled on this host".into(),
            fix: "add \"process_events\" to collectors in /etc/openvibes-agent/agent.toml, \
                  then restart the agent"
                .into(),
            command: None,
            fault: false,
        });
    };
    let alarms: AlarmHealth = serde_json::from_value(value.clone()).ok()?;
    let collector = serde_json::to_value(alarms.collector)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.replace('_', " ")))
        .unwrap_or_default();
    // Why not eBPF, when the agent tried it (absent when audit was forced).
    let why = alarms
        .fallback
        .map(|fallback| detail_words(fallback.detail));
    let then = |rest: String| why.map_or_else(|| rest.clone(), |why| format!("{why}, and {rest}"));
    let capability = alarms
        .fallback
        .is_some_and(|fallback| fallback.detail == FallbackDetail::Capability);
    let off = |reason, text, fix: String, command| AlarmsStatus::Off {
        reason,
        text,
        fix,
        command,
        fault: true,
    };
    Some(match alarms.source {
        Some(AlarmSource::None) => off(
            "no_source",
            then(format!(
                "kernel audit could not be read either ({collector})"
            )),
            if alarms.collector == CollectorOutcome::PermissionDenied {
                "give the agent CAP_AUDIT_READ (and CAP_BPF and CAP_PERFMON for eBPF): \
                 check AmbientCapabilities in `systemctl cat openvibes-agent` for a drop-in \
                 that removes them, then restart the agent"
                    .into()
            } else {
                "see why in `sudo journalctl -u openvibes-agent`, fix that, then restart the agent"
                    .into()
            },
            Some(RESTART),
        ),
        _ if !matches!(
            alarms.collector,
            CollectorOutcome::Ok | CollectorOutcome::NotFound
        ) =>
        {
            off(
                "reader_failed",
                format!("the agent's process-start reader is not working ({collector})"),
                "see why in `sudo journalctl -u openvibes-agent`, then restart the agent".into(),
                Some(RESTART),
            )
        }
        Some(AlarmSource::Ebpf) => AlarmsStatus::On { source: "ebpf" },
        _ if alarms
            .fallback
            .is_some_and(|fallback| !fallback.audit_rule_loaded) =>
        {
            off(
                "audit_not_set_up",
                then(
                    "no program start seen through audit yet: the exec audit rule is probably \
                 not loaded, or auditd is not running"
                        .into(),
                ),
                format!(
                    "make sure auditd is installed and running, then run the command below{}",
                    if capability {
                        "; or, to use eBPF instead, give the agent back CAP_BPF and CAP_PERFMON \
                     (check `systemctl cat openvibes-agent`) and restart it"
                    } else {
                        ""
                    }
                ),
                Some(AUDIT_FALLBACK),
            )
        }
        // Audit, or no source at all: agents before the eBPF watcher.
        _ => AlarmsStatus::On { source: "audit" },
    })
}

fn detail_words(detail: FallbackDetail) -> &'static str {
    match detail {
        FallbackDetail::NoBtf => "this kernel has no BTF",
        FallbackDetail::Capability => "the agent lacks CAP_BPF or CAP_PERFMON",
        FallbackDetail::Lockdown => "kernel lockdown forbids eBPF",
        FallbackDetail::LsmDenied => "a security module (SELinux or AppArmor) refused eBPF",
        FallbackDetail::Verifier => "the kernel refused the agent's eBPF program",
        FallbackDetail::Other => "eBPF could not be started (see the agent's log)",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{AUDIT_FALLBACK, AlarmsStatus, RESTART, alarms_status};

    /// A valid `health.alarms` from the protocol's fixture (audit after
    /// `no_btf`, rule loaded, collector `ok`), edited per test.
    fn alarms(edit: impl FnOnce(&mut Value)) -> Value {
        let beat: Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/v1/heartbeat/valid-alarms-fallback.json"
        ))
        .unwrap();
        let mut alarms = beat["health"]["alarms"].clone();
        edit(&mut alarms);
        alarms
    }

    fn status(edit: impl FnOnce(&mut Value)) -> Option<AlarmsStatus> {
        alarms_status(true, Some(&alarms(edit)))
    }

    struct Off {
        reason: &'static str,
        text: String,
        fix: String,
        command: Option<&'static str>,
        fault: bool,
    }

    fn off(status: Option<AlarmsStatus>) -> Off {
        match status {
            Some(AlarmsStatus::Off {
                reason,
                text,
                fix,
                command,
                fault,
            }) => Off {
                reason,
                text,
                fix,
                command,
                fault,
            },
            other => panic!("not off: {other:?}"),
        }
    }

    const ON_EBPF: Option<AlarmsStatus> = Some(AlarmsStatus::On { source: "ebpf" });
    const ON_AUDIT: Option<AlarmsStatus> = Some(AlarmsStatus::On { source: "audit" });

    fn ebpf(a: &mut Value) {
        a["source"] = json!("ebpf");
        a.as_object_mut().unwrap().remove("fallback");
    }

    #[test]
    fn never_reported_is_none() {
        assert_eq!(alarms_status(false, None), None);
    }

    #[test]
    fn no_alarms_object_is_not_enabled_and_no_fault() {
        for value in [None, Some(&Value::Null)] {
            let o = off(alarms_status(true, value));
            assert_eq!(o.reason, "not_enabled");
            assert!(o.fix.contains("process_events"), "{}", o.fix);
            assert_eq!(o.command, None, "words, not a command to paste");
            assert!(!o.fault);
        }
    }

    #[test]
    fn ebpf_is_on_also_before_the_first_program_start() {
        assert_eq!(status(ebpf), ON_EBPF);
        assert_eq!(
            status(|a| {
                ebpf(a);
                a["collector"] = json!("not_found");
            }),
            ON_EBPF
        );
    }

    #[test]
    fn missing_source_is_audit() {
        let old = |a: &mut Value| {
            let a = a.as_object_mut().unwrap();
            a.remove("source");
            a.remove("fallback");
        };
        assert_eq!(status(old), ON_AUDIT);
    }

    #[test]
    fn audit_with_rule_is_on() {
        assert_eq!(status(|_| {}), ON_AUDIT);
    }

    #[test]
    fn a_stopped_reader_is_off_whatever_the_source() {
        // The reader died (`internal`): the source stays, alarms do not.
        let o = off(status(|a| {
            ebpf(a);
            a["collector"] = json!("internal");
        }));
        assert_eq!(
            (o.reason, o.command, o.fault),
            ("reader_failed", Some(RESTART), true)
        );
        // A 0.2.5 agent whose audit socket failed.
        let o = off(status(|a| {
            let m = a.as_object_mut().unwrap();
            m.remove("source");
            m.remove("fallback");
            a["collector"] = json!("permission_denied");
        }));
        assert_eq!(o.reason, "reader_failed");
        assert!(o.text.contains("permission denied"), "{}", o.text);
    }

    #[test]
    fn fallback_without_rule_needs_auditd_and_the_fallback_command() {
        let o = off(status(|a| {
            a["fallback"]["audit_rule_loaded"] = json!(false);
            a["collector"] = json!("not_found");
        }));
        assert_eq!(o.reason, "audit_not_set_up");
        assert!(
            o.text.contains("no BTF") && o.text.contains("no program start seen through audit yet"),
            "{}",
            o.text
        );
        assert!(o.fix.contains("auditd"), "{}", o.fix);
        assert!(!o.fix.contains("CAP_BPF"), "{}", o.fix);
        assert_eq!(o.command, Some(AUDIT_FALLBACK));
        assert!(o.fault);
    }

    #[test]
    fn a_capability_fallback_also_names_the_ebpf_fix() {
        let o = off(status(|a| {
            a["fallback"] = json!({"detail": "capability", "audit_rule_loaded": false});
        }));
        assert!(o.fix.contains("CAP_BPF and CAP_PERFMON"), "{}", o.fix);
    }

    #[test]
    fn no_source_points_at_the_capability_or_the_log_never_audit_fallback() {
        let o = off(status(|a| {
            a["source"] = json!("none");
            a["collector"] = json!("permission_denied");
            a["fallback"] = json!({"detail": "capability", "audit_rule_loaded": false});
        }));
        assert_eq!(o.reason, "no_source");
        assert!(
            o.text.contains("CAP_BPF") && o.text.contains("permission denied"),
            "{}",
            o.text
        );
        assert!(o.fix.contains("CAP_AUDIT_READ"), "{}", o.fix);
        assert_eq!(o.command, Some(RESTART));
        // Audit forced (no fallback) and the socket failed for another reason:
        // eBPF was never tried, so the words do not blame it.
        let o = off(status(|a| {
            a["source"] = json!("none");
            a["collector"] = json!("unsupported");
            a.as_object_mut().unwrap().remove("fallback");
        }));
        assert!(!o.text.contains("eBPF"), "{}", o.text);
        assert!(o.fix.contains("journalctl"), "{}", o.fix);
    }

    #[test]
    fn each_detail_has_its_own_words() {
        let texts: std::collections::BTreeSet<String> = [
            "no_btf",
            "capability",
            "lockdown",
            "lsm_denied",
            "verifier",
            "other",
        ]
        .into_iter()
        .map(|detail| {
            off(status(|a| {
                a["fallback"] = json!({"detail": detail, "audit_rule_loaded": false});
            }))
            .text
        })
        .collect();
        assert_eq!(texts.len(), 6);
    }

    #[test]
    fn unparsable_alarms_is_unknown() {
        assert_eq!(alarms_status(true, Some(&json!("garbage"))), None);
    }
}
