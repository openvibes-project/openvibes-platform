use platform_assistant::{Area, Lookup, LookupError, LookupOutput, LookupRunner, StoreLookups};
use platform_store::{Pool, StoreError, assistant::AgentScope, console_read};
use serde_json::json;

/// What the asking user may read, by console permission: the assistant
/// shows no more than the matching console pages would.
pub(crate) struct Access {
    /// `agents.read`, equal to `compliance.read` (the endpoint checks).
    pub(crate) agents: console_read::AgentScope,
    /// `vulnerabilities.read`; `None` without it.
    pub(crate) vulnerabilities: Option<console_read::AgentScope>,
    /// `rules.read` (global only, as on the Rules page): every published
    /// rule. Without it, only rules with a finding in the agent scope.
    pub(crate) rules: bool,
    /// Internet lookups; `None` when the user may not use them.
    pub(crate) internet: Option<crate::assistant::fetch_client::Internet>,
}

/// Runs every lookup offered to the model (`platform_assistant::lookups::specs`)
/// within the user's console permissions. A lookup the user may not run is
/// still offered and answers [`LookupError::Forbidden`], so the model says
/// "you have no access" instead of "no data".
pub(crate) struct ConsoleReadLookups {
    /// Agent and finding scope.
    lookups: StoreLookups,
    /// Vulnerability scope; `None` without `vulnerabilities.read`.
    vulnerabilities: Option<StoreLookups>,
    /// `fleet_overview` mixes agents, findings and vulnerabilities, so it
    /// needs `vulnerabilities.read` with the agent scope.
    overview: bool,
    rules: bool,
    internet: Option<crate::assistant::fetch_client::Internet>,
    /// An internet lookup was attempted and did not succeed (not "off",
    /// not blocked).
    internet_failed: std::sync::atomic::AtomicBool,
    pool: Pool,
    scope: console_read::AgentScope,
    now: chrono::DateTime<chrono::Utc>,
}

/// The store's form of a console scope: asset groups become agent IDs.
async fn store_scope(
    pool: &Pool,
    scope: &console_read::AgentScope,
) -> Result<AgentScope, StoreError> {
    Ok(match scope {
        console_read::AgentScope::Global => AgentScope::All,
        console_read::AgentScope::AssetGroups(_) => {
            let client = pool.get().await.map_err(|_| StoreError::Unavailable)?;
            AgentScope::Only(console_read::agent_ids_in_scope(&client, scope).await?)
        }
    })
}

impl ConsoleReadLookups {
    pub(crate) async fn for_user(
        pool: Pool,
        access: Access,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Self, StoreError> {
        let agent_scope = store_scope(&pool, &access.agents).await?;
        let overview = access.vulnerabilities.as_ref() == Some(&access.agents);
        let vulnerabilities = match &access.vulnerabilities {
            None => None,
            Some(_) if overview => Some(agent_scope.clone()),
            Some(scope) => Some(store_scope(&pool, scope).await?),
        }
        .map(|scope| StoreLookups::new(pool.clone(), scope, now));
        Ok(Self {
            lookups: StoreLookups::new(pool.clone(), agent_scope, now),
            vulnerabilities,
            overview,
            rules: access.rules,
            internet: access.internet,
            internet_failed: std::sync::atomic::AtomicBool::new(false),
            pool,
            scope: access.agents,
            now,
        })
    }
}

impl ConsoleReadLookups {
    /// An internet lookup was attempted for this answer and failed
    /// (unreachable, too large, rate-limited; a blocked query is no failure).
    pub(crate) fn internet_failed(&self) -> bool {
        self.internet_failed
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The internet lookups that went out for this answer.
    pub(crate) fn internet_sent(&self) -> Vec<crate::assistant::fetch_client::Sent> {
        self.internet.as_ref().map_or_else(Vec::new, |internet| {
            internet
                .sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        })
    }
}

impl LookupRunner for ConsoleReadLookups {
    async fn run(&self, lookup: &Lookup, items: u32) -> Result<LookupOutput, LookupError> {
        let forbidden = |area| Err(LookupError::Forbidden(area));
        match lookup {
            // Host services and software read host data, guarded by
            // agents.read like agent_summary (and the Assets and Software
            // pages), with the agent scope.
            Lookup::SearchFindings { .. }
            | Lookup::FindingEndpoints { .. }
            | Lookup::HostServices { .. }
            | Lookup::Software { .. } => self.lookups.run(lookup, items).await,
            Lookup::HostVulnerabilities { .. } | Lookup::VulnerabilityHosts { .. } => {
                match &self.vulnerabilities {
                    Some(lookups) => lookups.run(lookup, items).await,
                    None => forbidden(Area::Vulnerabilities),
                }
            }
            Lookup::FleetOverview { .. } if self.overview => self.lookups.run(lookup, items).await,
            Lookup::FleetOverview { .. } => forbidden(Area::Vulnerabilities),
            Lookup::RuleDescription { rule, .. } => {
                // Without rules.read: the latest published definition of a
                // rule the user has findings for (same rule id, never another
                // host's data; the Compliance page shows the version each
                // finding was evaluated against). Such a rule is only read
                // from a set it was found in (`rule_set_for_description`).
                if !self.rules && self.lookups.rule_sets_for(rule).await?.is_empty() {
                    return forbidden(Area::Rules);
                }
                self.lookups.run(lookup, items).await
            }
            Lookup::Reference { .. } | Lookup::WebSearch { .. } => match &self.internet {
                Some(internet) => {
                    let result = internet.run(&self.pool, lookup).await;
                    if match &result {
                        Ok(output) => crate::assistant::fetch_client::is_failure(output),
                        Err(_) => true,
                    } {
                        self.internet_failed
                            .store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                    result
                }
                None => Err(crate::assistant::fetch_client::forbidden()),
            },
            Lookup::AgentSummary { agent } => {
                let client = self.pool.get().await.map_err(|_| LookupError::Store)?;
                let mut matches =
                    console_read::agent_matches_in_scope(&client, agent, self.now, &self.scope)
                        .await
                        .map_err(|_| LookupError::Store)?;
                if matches.len() > 1 {
                    return Err(LookupError::Ambiguous);
                }
                let records = matches
                    .drain(..)
                    .map(|record| {
                        let state = match record.state {
                            console_read::AgentState::Active => "seen recently",
                            console_read::AgentState::Stale => {
                                if record.last_seen_at.is_some() {
                                    "offline"
                                } else {
                                    "never seen"
                                }
                            }
                            console_read::AgentState::Revoked => "revoked",
                            console_read::AgentState::Imported => "imported",
                        };
                        json!({
                            "cite": format!("[agent:{}]", record.agent_id),
                            "hostname": record.hostname,
                            "state": state,
                            "last_seen": record.last_seen_at.map(|value| value.to_rfc3339()),
                        })
                    })
                    .collect::<Vec<_>>();
                Ok(LookupOutput {
                    data: json!({ "items": records, "omitted": 0 }),
                })
            }
        }
    }
}
