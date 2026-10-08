//! Threat alarms on one host (eBPF watcher, spec 2026-10-08 §5): on, and
//! from which source, or off with why and the one command that fixes it.
//! Derived from the stored `health.alarms` when read, never stored. Shared by
//! the console and the admin CLI, so both say the same words.

use openvibes_core::{AlarmHealth, AlarmSource, FallbackDetail};

/// Sets the audit fallback up on the host (the agent package ships it).
pub const AUDIT_FALLBACK: &str = "sudo /usr/libexec/openvibes-agent/audit-fallback";

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
        /// `not_enabled`, `audit_not_set_up` or `no_source`.
        reason: &'static str,
        /// Why, in words.
        text: String,
        /// The command or setting that turns them on, shown verbatim.
        fix: String,
        /// Off by a fault, not by the admin's choice (the Hosts list badges these).
        fault: bool,
    },
}

/// The status from a host's last report. `reported`: the host sent a health
/// report; `alarms`: its stored `health -> 'alarms'` (absent or JSON null when
/// process events are not enabled). `None` before a report, or when the stored
/// value does not parse.
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
                  then sudo systemctl restart openvibes-agent"
                .into(),
            fault: false,
        });
    };
    let alarms: AlarmHealth = serde_json::from_value(value.clone()).ok()?;
    let why = alarms
        .fallback
        .map_or("eBPF could not be started", |fallback| {
            detail_words(fallback.detail)
        });
    Some(match (alarms.source, alarms.fallback) {
        (Some(AlarmSource::Ebpf), _) => AlarmsStatus::On { source: "ebpf" },
        (Some(AlarmSource::None), _) => AlarmsStatus::Off {
            reason: "no_source",
            text: format!(
                "{why}, and kernel audit could not be read either ({})",
                serde_json::to_value(alarms.collector)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_default()
                    .replace('_', " ")
            ),
            fix: format!("{AUDIT_FALLBACK} && sudo systemctl restart openvibes-agent"),
            fault: true,
        },
        (_, Some(fallback)) if !fallback.audit_rule_loaded => AlarmsStatus::Off {
            reason: "audit_not_set_up",
            text: format!(
                "{why}, and no program start seen through audit yet: \
                 the exec audit rule is probably not loaded"
            ),
            fix: AUDIT_FALLBACK.into(),
            fault: true,
        },
        // Audit, or no source at all: agents before the eBPF watcher.
        _ => AlarmsStatus::On { source: "audit" },
    })
}

fn detail_words(detail: FallbackDetail) -> &'static str {
    match detail {
        FallbackDetail::NoBtf => "this kernel has no BTF",
        FallbackDetail::Capability => {
            "the agent lacks CAP_BPF or CAP_PERFMON (check its systemd unit)"
        }
        FallbackDetail::Lockdown => "kernel lockdown forbids eBPF",
        FallbackDetail::LsmDenied => "a security module (SELinux or AppArmor) refused eBPF",
        FallbackDetail::Verifier => "the kernel refused the agent's eBPF program",
        FallbackDetail::Other => "eBPF could not be started (see the agent's log)",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};

    use super::{AUDIT_FALLBACK, AlarmsStatus, alarms_status};

    /// A valid `health.alarms` from the protocol's fixture, edited per test.
    fn alarms(edit: impl FnOnce(&mut Value)) -> Value {
        let beat: Value = serde_json::from_str(include_str!(
            "../../../protocol/fixtures/v1/heartbeat/valid-alarms-fallback.json"
        ))
        .unwrap();
        let mut alarms = beat["health"]["alarms"].clone();
        edit(&mut alarms);
        alarms
    }

    fn off(status: Option<AlarmsStatus>) -> (&'static str, String, String, bool) {
        match status {
            Some(AlarmsStatus::Off {
                reason,
                text,
                fix,
                fault,
            }) => (reason, text, fix, fault),
            other => panic!("not off: {other:?}"),
        }
    }

    #[test]
    fn never_reported_is_none() {
        assert_eq!(alarms_status(false, None), None);
    }

    #[test]
    fn no_alarms_object_is_not_enabled() {
        for value in [None, Some(&Value::Null)] {
            let (reason, _, fix, fault) = off(alarms_status(true, value));
            assert_eq!(reason, "not_enabled");
            assert!(fix.contains("process_events"), "{fix}");
            assert!(!fault);
        }
    }

    #[test]
    fn ebpf_is_on() {
        let v = alarms(|a| {
            a["source"] = json!("ebpf");
            a.as_object_mut().unwrap().remove("fallback");
        });
        assert_eq!(
            alarms_status(true, Some(&v)),
            Some(AlarmsStatus::On { source: "ebpf" })
        );
    }

    #[test]
    fn missing_source_is_audit() {
        let v = alarms(|a| {
            let a = a.as_object_mut().unwrap();
            a.remove("source");
            a.remove("fallback");
        });
        assert_eq!(
            alarms_status(true, Some(&v)),
            Some(AlarmsStatus::On { source: "audit" })
        );
    }

    #[test]
    fn audit_with_rule_is_on() {
        let v = alarms(|a| a["fallback"]["audit_rule_loaded"] = json!(true));
        assert_eq!(
            alarms_status(true, Some(&v)),
            Some(AlarmsStatus::On { source: "audit" })
        );
    }

    #[test]
    fn fallback_without_rule_is_off_with_the_fallback_command() {
        let v = alarms(|a| a["fallback"]["audit_rule_loaded"] = json!(false));
        let (reason, text, fix, fault) = off(alarms_status(true, Some(&v)));
        assert_eq!(reason, "audit_not_set_up");
        assert!(
            text.contains("no BTF") && text.contains("no program start seen through audit yet"),
            "{text}"
        );
        assert_eq!(fix, AUDIT_FALLBACK);
        assert!(fault);
    }

    #[test]
    fn none_is_off_and_needs_a_restart() {
        let v = alarms(|a| {
            a["source"] = json!("none");
            a["collector"] = json!("permission_denied");
            a["fallback"] = json!({"detail": "capability", "audit_rule_loaded": false});
        });
        let (reason, text, fix, fault) = off(alarms_status(true, Some(&v)));
        assert_eq!(reason, "no_source");
        assert!(
            text.contains("CAP_BPF") && text.contains("permission denied"),
            "{text}"
        );
        assert_eq!(
            fix,
            format!("{AUDIT_FALLBACK} && sudo systemctl restart openvibes-agent")
        );
        assert!(fault);
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
            let v =
                alarms(|a| a["fallback"] = json!({"detail": detail, "audit_rule_loaded": false}));
            off(alarms_status(true, Some(&v))).1
        })
        .collect();
        assert_eq!(texts.len(), 6);
    }

    #[test]
    fn unparsable_alarms_is_unknown() {
        assert_eq!(alarms_status(true, Some(&json!("garbage"))), None);
    }
}
