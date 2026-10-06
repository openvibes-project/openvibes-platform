//! Which hosts run the site's own rule sets (design D5): per set, how many
//! are current, behind, refusing a bundle, or missing the set from their
//! `agent.toml`; and the lines to paste into an agent that lacks it.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use platform_store::{
    console_read::{AgentScope, HostRuleSets},
    rule_drafts::{SITE, SITE_ALARMS},
};
use serde::Serialize;
use utoipa::ToSchema;

use crate::{
    Permission, ProblemDetails,
    problem::problem_response,
    router::{AuthHttpState, authenticated_permission, unavailable_auth},
};

/// Most hosts listed with their state; counts always cover every host.
const LISTED: usize = 200;

/// One site set across the fleet.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, ToSchema)]
pub struct SiteSetFleet {
    /// `site` or `site-alarms`.
    pub rule_set_id: String,
    /// The published version; absent before the first publish.
    pub published_version: Option<i64>,
    /// Hosts running the published version (or any, before a publish).
    pub current: usize,
    /// Hosts running an older version.
    pub behind: usize,
    /// Hosts that refused the bundle the platform serves.
    pub refused: usize,
    /// Hosts whose `agent.toml` doesn't list the set, or that haven't
    /// accepted a bundle yet.
    pub missing: usize,
}

/// One host's state for each site set.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, ToSchema)]
pub struct SiteHostFleet {
    /// Agent id.
    pub agent_id: String,
    /// Hostname, when known.
    pub hostname: Option<String>,
    /// `current`, `behind`, `refused` or `missing` for `site`.
    pub site: String,
    /// The same for `site-alarms`.
    pub site_alarms: String,
}

/// The fleet's site rule sets.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct SiteFleet {
    /// Both site sets.
    pub sets: Vec<SiteSetFleet>,
    /// Hosts that have sent a health report (the counts cover these).
    pub reporting: usize,
    /// Hosts that haven't sent one yet; they are in no count.
    pub not_reporting: usize,
    /// Hosts not current in some set, up to 200.
    pub hosts: Vec<SiteHostFleet>,
    /// More than 200 hosts are not current.
    pub hosts_truncated: bool,
    /// The two `[[rule_sets]]` blocks for `agent.toml`, when the platform
    /// trusts a key for both sets.
    pub paste: Option<String>,
}

fn state(host: &HostRuleSets, set: &str, published: Option<i64>) -> &'static str {
    let Some(entry) = host.rule_sets.iter().find(|entry| entry.id == set) else {
        return "missing";
    };
    if entry.refused.is_some() {
        return "refused";
    }
    match (entry.version, published) {
        (None, _) => "missing",
        (Some(version), Some(published)) if version < published => "behind",
        _ => "current",
    }
}

pub(crate) fn summarize(
    hosts: &[HostRuleSets],
    published: [Option<i64>; 2],
    paste: Option<String>,
) -> SiteFleet {
    let sets = [SITE, SITE_ALARMS];
    let mut out = SiteFleet {
        sets: sets
            .iter()
            .zip(published)
            .map(|(set, version)| SiteSetFleet {
                rule_set_id: (*set).to_owned(),
                published_version: version,
                ..SiteSetFleet::default()
            })
            .collect(),
        reporting: 0,
        not_reporting: 0,
        hosts: Vec::new(),
        hosts_truncated: false,
        paste,
    };
    for host in hosts {
        if !host.reported {
            out.not_reporting += 1;
            continue;
        }
        out.reporting += 1;
        let states = [
            state(host, SITE, published[0]),
            state(host, SITE_ALARMS, published[1]),
        ];
        for (set, state) in out.sets.iter_mut().zip(states) {
            match state {
                "current" => set.current += 1,
                "behind" => set.behind += 1,
                "refused" => set.refused += 1,
                _ => set.missing += 1,
            }
        }
        if states.iter().any(|state| *state != "current") {
            if out.hosts.len() < LISTED {
                out.hosts.push(SiteHostFleet {
                    agent_id: host.agent_id.clone(),
                    hostname: host.hostname.clone(),
                    site: states[0].to_owned(),
                    site_alarms: states[1].to_owned(),
                });
            } else {
                out.hosts_truncated = true;
            }
        }
    }
    out
}

#[utoipa::path(get, path = "/api/v1/site-rules/fleet", tag = "rules",
    responses((status = 200, description = "Which hosts run the site rule sets", body = crate::site_fleet::SiteFleet),
        (status = 403, description = "Needs rules.write and global access", body = crate::ProblemDetails, content_type = "application/problem+json")))]
pub(crate) async fn site_fleet(State(state): State<AuthHttpState>, headers: HeaderMap) -> Response {
    let (scope, _) =
        match authenticated_permission(&state, &headers, Permission::RulesWrite, false).await {
            Ok(context) => context,
            Err(response) => return response,
        };
    if !matches!(scope, AgentScope::Global) {
        return problem_response(ProblemDetails::new(
            StatusCode::FORBIDDEN,
            "permission_denied",
            "Access is not available",
        ));
    }
    let Ok(client) = state.pool.get().await else {
        return unavailable_auth();
    };
    let Ok(hosts) = platform_store::console_read::host_rule_sets(&client).await else {
        return unavailable_auth();
    };
    let mut published = [None, None];
    let mut block = String::new();
    let mut complete = true;
    for (index, set) in [SITE, SITE_ALARMS].into_iter().enumerate() {
        let (Ok(sets), Ok(keys)) = (
            platform_store::rules::list(&client).await,
            platform_store::rules::active_trust_keys(&client, set).await,
        ) else {
            return unavailable_auth();
        };
        published[index] = sets
            .iter()
            .find(|row| row.rule_set_id == set)
            .and_then(|row| row.current_version);
        match keys.first() {
            Some((key, issuer)) => block.push_str(&format!(
                "[[rule_sets]]\nid = \"{set}\"\ntrusted_keys = [{{ issuer_key_id = \"{issuer}\", public_key = \"{}\" }}]\n",
                URL_SAFE_NO_PAD.encode(key)
            )),
            None => complete = false,
        }
    }
    Json(summarize(&hosts, published, complete.then_some(block))).into_response()
}

#[cfg(test)]
mod tests {
    use platform_store::console_read::{AgentRuleSet, HostRuleSets};

    use super::summarize;

    fn host(id: &str, reported: bool, sets: &[(&str, Option<i64>, Option<&str>)]) -> HostRuleSets {
        HostRuleSets {
            agent_id: id.to_owned(),
            hostname: None,
            reported,
            rule_sets: sets
                .iter()
                .map(|(set, version, refused)| AgentRuleSet {
                    id: (*set).to_owned(),
                    version: *version,
                    expires_at_ms: None,
                    refused: refused.map(str::to_owned),
                })
                .collect(),
        }
    }

    #[test]
    fn counts_each_state_and_lists_only_hosts_that_need_attention() {
        let hosts = [
            host(
                "a",
                true,
                &[("site", Some(3), None), ("site-alarms", Some(1), None)],
            ),
            host(
                "b",
                true,
                &[("site", Some(2), None), ("site-alarms", Some(1), None)],
            ),
            host("c", true, &[("baseline", Some(9), None)]),
            host(
                "d",
                true,
                &[
                    ("site", Some(3), Some("signature")),
                    ("site-alarms", None, None),
                ],
            ),
            host("e", false, &[]),
        ];
        let fleet = summarize(&hosts, [Some(3), Some(1)], None);
        assert_eq!((fleet.reporting, fleet.not_reporting), (4, 1));
        let site = &fleet.sets[0];
        assert_eq!(
            (site.current, site.behind, site.refused, site.missing),
            (1, 1, 1, 1)
        );
        let alarms = &fleet.sets[1];
        assert_eq!(
            (
                alarms.current,
                alarms.behind,
                alarms.refused,
                alarms.missing
            ),
            (2, 0, 0, 2)
        );
        let listed: Vec<&str> = fleet.hosts.iter().map(|h| h.agent_id.as_str()).collect();
        assert_eq!(listed, ["b", "c", "d"]);
    }

    #[test]
    fn before_a_publish_any_version_is_current() {
        let hosts = [host(
            "a",
            true,
            &[("site", Some(1), None), ("site-alarms", Some(1), None)],
        )];
        let fleet = summarize(&hosts, [None, None], None);
        assert!(fleet.hosts.is_empty());
        assert_eq!(fleet.sets[0].current, 1);
    }
}
