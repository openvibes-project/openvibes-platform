//! The Related card of a vulnerability's page (step 5b ruling 12): open
//! alarms on its hosts, open cases holding its pairs, other CVEs on the
//! same packages, and whether a scope reaches its hosts.

use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
    host_summary::{RANK, Top, TopAlarm, top},
    vuln_list::VulnSeverity,
    vuln_summary_sql as sql,
};

/// Most cases the Related card names.
const CASES: i64 = 20;

/// A case holding a pair.
#[derive(Clone, Debug)]
pub struct CaseRef {
    /// Case id.
    pub id: String,
    /// Shown as `C-<number>`.
    pub number: i64,
    /// Title.
    pub title: String,
}

/// Other keys in reach on the same package names.
#[derive(Clone, Debug, Default)]
pub struct SamePackage {
    /// How many.
    pub cves: i64,
    /// How many per severity, most severe first.
    pub severities: Vec<(VulnSeverity, i64)>,
}

/// The Related card.
#[derive(Clone, Debug)]
pub struct Related {
    /// Open alarms on the hosts, with `alarms.read` on them.
    pub alarms: Option<Top<TopAlarm>>,
    /// Open cases holding a pair, with `cases.read`.
    pub cases: Option<Vec<CaseRef>>,
    /// Same package.
    pub same_package: SamePackage,
}

/// Open agent alarms on `agents` that `scope` reaches: the top three, most
/// severe first, and the total.
pub(crate) async fn alarms(
    client: &Client,
    agents: &[String],
    scope: &AgentScope,
) -> Result<Top<TopAlarm>, StoreError> {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let rows = client
        .query(
            &format!(
                "SELECT al.id, al.rule_id, al.message, al.severity, al.last_seen, count(*) OVER ()
                 FROM alarms al JOIN agents a ON a.agent_id = al.agent_id
                 WHERE al.agent_id = ANY($3) AND al.state = 'open' AND al.source = 'agent' AND {visible}
                 ORDER BY {RANK}, al.last_seen DESC, al.id DESC LIMIT 3"
            ),
            &[&scope.is_global(), &scope.group_ids(), &agents],
        )
        .await?;
    Ok(top(&rows, |r| TopAlarm {
        id: r.get(0),
        rule_id: r.get(1),
        message: r.get(2),
        severity: r.get(3),
        last_seen: r.get(4),
    }))
}

/// Open cases holding a pair of `agents` and `advisories` whose host
/// `scope` reaches, newest first.
pub(crate) async fn cases(
    client: &Client,
    agents: &[String],
    advisories: &[String],
    scope: &AgentScope,
) -> Result<Vec<CaseRef>, StoreError> {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let rows = client
        .query(
            &format!(
                "SELECT DISTINCT c.case_id::text, c.number, c.title
                 FROM case_items ci JOIN cases c ON c.case_id = ci.case_id
                 JOIN agents a ON a.agent_id = ci.agent_id
                 WHERE ci.kind = 'vulnerability' AND ci.active AND ci.agent_id = ANY($3)
                   AND starts_with(ci.ref, ci.agent_id || '/')
                   AND substr(ci.ref, length(ci.agent_id) + 2) = ANY($4) AND {visible}
                 ORDER BY c.number DESC LIMIT {CASES}"
            ),
            &[&scope.is_global(), &scope.group_ids(), &agents, &advisories],
        )
        .await?;
    Ok(rows
        .iter()
        .map(|r| CaseRef {
            id: r.get(0),
            number: r.get(1),
            title: r.get(2),
        })
        .collect())
}

/// Other keys in reach on `names`, but `key`.
pub(crate) async fn same_package(
    client: &Client,
    scope: &AgentScope,
    names: &[String],
    key: &str,
) -> Result<SamePackage, StoreError> {
    let rows = client
        .query(
            &sql::same_package(),
            &[&scope.is_global(), &scope.group_ids(), &names, &key],
        )
        .await?;
    let severities: Vec<(VulnSeverity, i64)> = rows
        .iter()
        .map(|r| {
            let s: Option<&str> = r.get(0);
            (
                s.and_then(VulnSeverity::parse)
                    .unwrap_or(VulnSeverity::Unrated),
                r.get(1),
            )
        })
        .collect();
    Ok(SamePackage {
        cves: severities.iter().map(|s| s.1).sum(),
        severities,
    })
}

/// Whether `scope` reaches one of `agents` (`agent_visibility`'s rule).
pub async fn reaches_any(
    client: &Client,
    agents: &[String],
    scope: &AgentScope,
) -> Result<bool, StoreError> {
    if scope.is_global() {
        return Ok(!agents.is_empty());
    }
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    Ok(client
        .query_one(
            &format!(
                "SELECT EXISTS (SELECT 1 FROM agents a WHERE a.agent_id = ANY($3) AND {visible})"
            ),
            &[&false, &scope.group_ids(), &agents],
        )
        .await?
        .get(0))
}
