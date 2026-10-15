use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// What the editor sends for one rule: everything but its id and version.
#[derive(Clone, Debug, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct RuleDraftInput {
    /// Short title shown on findings or alarms.
    pub title: String,
    /// `info`, `low`, `medium`, `high` or `critical`.
    pub severity: String,
    /// Confidence in a match, 0 to 100.
    pub confidence: u8,
    /// CEL expression over `facts[...]` (findings) or `event[...]` (alarms).
    pub expression: String,
    /// Message on a match.
    pub finding_message: String,
    /// Alarm rules only: the programs (exe paths or basenames) an event must
    /// match before the expression runs; one to eight.
    pub programs: Option<Vec<String>>,
    /// MITRE ATT&CK pairs the rule covers (P18), primary first.
    #[serde(default)]
    pub attack: Option<Vec<super::coverage::AttackPairInput>>,
}

/// One saved draft rule.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleDraftView {
    /// `site` (findings) or `site-alarms` (alarms).
    pub rule_set_id: String,
    /// The rule's id within the set.
    pub rule_id: String,
    /// The rule's version: raised each time a save changes it.
    pub version: u64,
    /// Title.
    pub title: String,
    /// Severity.
    pub severity: String,
    /// Confidence, 0 to 100.
    pub confidence: u8,
    /// CEL expression.
    pub expression: String,
    /// Message on a match.
    pub finding_message: String,
    /// Alarm rules: the program prefilter.
    pub programs: Option<Vec<String>>,
    /// Its ATT&CK pairs, resolved against the bundled release.
    pub attack: Vec<super::coverage::AttackPairView>,
    /// Who last saved it.
    pub updated_by: String,
    /// When (RFC 3339).
    pub updated_at: String,
}

/// The drafts of one rule set.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleDraftList {
    /// By rule id.
    pub items: Vec<RuleDraftView>,
}

/// One thing wrong with a draft.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, ToSchema)]
pub struct RuleProblem {
    /// The field it concerns: `id`, `title`, `severity`, `confidence`,
    /// `expression`, `finding_message`, `programs`, `attack` or `rule`.
    pub field: String,
    /// What is wrong.
    pub message: String,
}

/// The result of checking a draft.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct RuleCheck {
    /// Whether the agent would accept it.
    pub ok: bool,
    /// Why not, when it would not.
    pub problems: Vec<RuleProblem>,
}

/// What publishing would change: the drafts against the published set.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct DraftChanges {
    /// The set's current published version; absent before the first publish.
    pub published_version: Option<i64>,
    /// Rules in the drafts but not published.
    pub added: Vec<String>,
    /// Rules in both, whose content differs.
    pub changed: Vec<String>,
    /// Published rules the drafts no longer have.
    pub removed: Vec<String>,
    /// Rules in both, the same.
    pub unchanged: usize,
}

/// The password the signer checks again before it signs.
#[derive(Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct PublishDraftsRequest {
    /// The signed-in user's password, typed again for this publish.
    pub password: String,
}

/// A published draft set.
#[derive(Clone, Debug, Serialize, ToSchema)]
pub struct PublishedDrafts {
    /// `site` or `site-alarms`.
    pub rule_set_id: String,
    /// The version now published.
    pub version: i64,
    /// When the signed bundle expires, in Unix milliseconds.
    pub expires_at_ms: i64,
    /// Rules in the bundle.
    pub rules: usize,
}
