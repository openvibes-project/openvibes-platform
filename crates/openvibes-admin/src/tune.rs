//! Pure decisions for `openvibes-admin assistant tune`: no IO.
use std::collections::{BTreeMap, BTreeSet};

pub const DEFAULT_THREADS: u32 = 4;
pub const DEFAULT_GPU_LAYERS: u32 = 0;
const THREADS_KEY: &str = "OPENVIBES_LLM_THREADS";
const GPU_KEY: &str = "OPENVIBES_LLM_GPU_LAYERS";

/// Physical cores from the sysfs `thread_siblings_list` strings (one per
/// logical CPU); without them, assume two hardware threads per core.
pub fn physical_cores(core_lists: &[String], logical: usize) -> u32 {
    if core_lists.is_empty() {
        return (logical / 2).max(1) as u32;
    }
    core_lists.iter().collect::<BTreeSet<_>>().len() as u32
}

/// Keep two cores free for the host, within 2..=16.
pub fn threads_for(physical: u32) -> u32 {
    physical.saturating_sub(2).clamp(2, 16)
}

pub struct Plan {
    pub threads: Option<u32>,
    pub gpu_layers: Option<u32>,
    pub left_alone: Vec<&'static str>,
}

/// The value without surrounding whitespace and one layer of matching quotes.
pub fn unquote(value: &str) -> &str {
    let v = value.trim();
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|r| r.strip_suffix(q)) {
            return inner.trim();
        }
    }
    v
}

/// A key counts as operator-set when its value differs from the packaged
/// default; such keys are `None` (left alone).
pub fn plan(llm_conf: &BTreeMap<String, String>, threads: u32) -> Plan {
    let mut left_alone = Vec::new();
    let mut pick = |key: &'static str, default: u32, ours: u32| {
        let set = llm_conf
            .get(key)
            .is_some_and(|v| unquote(v).parse() != Ok(default));
        if set {
            left_alone.push(key);
        }
        (!set).then_some(ours)
    };
    let threads = pick(THREADS_KEY, DEFAULT_THREADS, threads);
    let gpu_layers = pick(GPU_KEY, DEFAULT_GPU_LAYERS, DEFAULT_GPU_LAYERS);
    Plan {
        threads,
        gpu_layers,
        left_alone,
    }
}

pub fn tuning_conf(plan: &Plan) -> String {
    let mut out =
        String::from("# Written by `openvibes-admin assistant tune`; rerun it to refresh.\n");
    for (key, v) in [(THREADS_KEY, plan.threads), (GPU_KEY, plan.gpu_layers)] {
        if let Some(v) = v {
            out.push_str(&format!("{key}={v}\n"));
        }
    }
    out
}

macro_rules! para {
    () => {
        "The platform collects facts about each endpoint, such as installed packages, open ports, running services and configuration files, and compares them with signed rules. A rule says which condition is a problem, how serious it is, and what an operator can do about it. Findings are queued on the endpoint, delivered to the ingest service over a mutually authenticated connection, and stored in the database, where the console lists them by endpoint, by rule and by age. Operators can silence a rule for one endpoint, group endpoints by role, and decide which findings deserve a notification. The agent is designed to stay small: it sleeps between collections, caps its memory, and drops the oldest queued findings first when the network is away for a long time. "
    };
}

/// A fixed, neutral prompt of about 750 tokens for the timed call.
pub const TUNE_PROMPT: &str = concat!(para!(), para!(), para!(), para!());

pub enum Deadline {
    Keep,
    Raise(u32),
}

/// Raise to min(180, ceil(2t)) only when t > half the current deadline and
/// that is higher; never lowers.
pub fn deadline(seconds_per_call: f64, current: u32) -> Deadline {
    let new = ((2.0 * seconds_per_call).ceil().min(180.0)) as u32;
    if seconds_per_call > 0.5 * f64::from(current) && new > current {
        Deadline::Raise(new)
    } else {
        Deadline::Keep
    }
}

pub fn summary(threads: u32, alias: &str, t: f64, raised: Option<u32>) -> String {
    let secs = if t < 1.0 {
        "<1".to_string()
    } else {
        format!("{}", t.round() as u64)
    };
    let mut s = format!("assistant: CPU ({threads} threads) · model {alias} · ~{secs} s per call");
    if let Some(d) = raised {
        s.push_str(&format!(" · deadline raised to {d} s"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cores_from_sibling_lists() {
        let lists = ["0,12", "1,13", "0,12", "1,13"].map(String::from);
        assert_eq!(physical_cores(&lists, 4), 2);
        assert_eq!(physical_cores(&[], 8), 4);
        assert_eq!(physical_cores(&[], 1), 1);
    }
    #[test]
    fn threads_keep_two_cores_free_within_bounds() {
        assert_eq!(threads_for(12), 10);
        assert_eq!(threads_for(2), 2);
        assert_eq!(threads_for(1), 2);
        assert_eq!(threads_for(64), 16);
    }
    #[test]
    fn operator_values_are_left_alone() {
        let mut conf = BTreeMap::new();
        conf.insert("OPENVIBES_LLM_THREADS".into(), "6".into());
        conf.insert("OPENVIBES_LLM_GPU_LAYERS".into(), "0".into());
        let p = plan(&conf, 10);
        assert_eq!(p.threads, None);
        assert_eq!(p.gpu_layers, Some(0));
        assert_eq!(p.left_alone, ["OPENVIBES_LLM_THREADS"]);
        conf.insert("OPENVIBES_LLM_THREADS".into(), "4".into());
        assert_eq!(plan(&conf, 10).threads, Some(10));
    }
    #[test]
    fn tuning_conf_lists_only_set_keys() {
        let c = tuning_conf(&Plan {
            threads: Some(10),
            gpu_layers: None,
            left_alone: vec![],
        });
        assert!(c.starts_with('#') && c.contains("openvibes-admin assistant tune"));
        assert!(c.contains("OPENVIBES_LLM_THREADS=10\n") && !c.contains("GPU_LAYERS"));
    }
    #[test]
    fn deadline_rises_only_when_slow_and_never_drops() {
        assert!(matches!(deadline(20.0, 60), Deadline::Keep));
        assert!(matches!(deadline(40.0, 60), Deadline::Raise(80)));
        assert!(matches!(deadline(120.0, 60), Deadline::Raise(180)));
        assert!(matches!(deadline(100.0, 300), Deadline::Keep));
    }
    #[test]
    fn deadline_boundaries_keep() {
        assert!(matches!(deadline(30.0, 60), Deadline::Keep));
        assert!(matches!(deadline(500.0, 180), Deadline::Keep));
    }
    #[test]
    fn quoted_and_padded_defaults_are_defaults() {
        for v in ["4 ", "\"4\"", " '4' "] {
            let conf = BTreeMap::from([("OPENVIBES_LLM_THREADS".to_string(), v.to_string())]);
            assert_eq!(plan(&conf, 10).threads, Some(10), "{v:?}");
        }
    }
    #[test]
    fn prompt_is_about_750_tokens() {
        assert!(
            (2600..3600).contains(&TUNE_PROMPT.len()),
            "{}",
            TUNE_PROMPT.len()
        );
    }
    #[test]
    fn summary_line() {
        assert_eq!(
            summary(10, "qwen3-4b", 8.4, None),
            "assistant: CPU (10 threads) · model qwen3-4b · ~8 s per call"
        );
        assert_eq!(
            summary(2, "qwen3-4b", 40.2, Some(81)),
            "assistant: CPU (2 threads) · model qwen3-4b · ~40 s per call · deadline raised to 81 s"
        );
        assert!(summary(2, "m", 0.3, None).contains("~<1 s"));
    }
}
