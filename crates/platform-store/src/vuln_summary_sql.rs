//! The SQL of a vulnerability's page (step 5b rulings 2, 9, 12): the pairs
//! of one key, expanded host by host (one CVE has at most a few pairs per
//! host), under the Vulnerabilities list's definitions — fixable rows with
//! its pair state and confidence side, pairs without a fix held once per
//! host and advisory while a fixable row is unfixed, CPE matches for the
//! CVE. Only fixed internal strings are formatted in; every value is bound.
//!
//! Parameters of [`pairs`]: `$1` global scope, `$2` scope group ids, `$3`
//! the advisories naming the key, `$4` the CVE (NULL for a CVE-less
//! advisory), `$5` today.

use chrono::NaiveDate;

use crate::{
    Client, StoreError,
    console_read::{AgentScope, agent_visibility},
    vuln_list_sql::{LOW_CONFIDENCE, PAIR_STATE},
    vuln_summary::Lookup,
    vulns::INSTALLED,
};

/// CTEs `hosts` (the agents in reach) and `pairs` (the key's pairs on
/// them). Lower-confidence pairs show only when the key has no other, as
/// the list shows them only under their own signal.
pub(crate) fn pairs() -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    let state = PAIR_STATE.replace("$13", "$5");
    format!(
        "hosts AS MATERIALIZED (
  SELECT a.agent_id, a.hostname, a.os_id, a.os_release, host(a.last_address) AS address,
         console_distribution_name(a.distribution) AS os
  FROM agents a WHERE {visible}),
pairs0 AS MATERIALIZED (
  SELECT v.agent_id, v.advisory_id, a.os_id, a.os_version, COALESCE({state}, 'open') AS state,
         t.assigned_to AS assignee, COALESCE(t.version, 0)::bigint AS version, v.packages,
         v.fixed_at IS NULL AND v.reboot_needed AS reboot, {LOW_CONFIDENCE} AS lc,
         NULL::real AS cvss, NULL::int AS confidence, NULL::text AS basis, a.source, true AS fixable
  FROM vulnerabilities v JOIN hosts h ON h.agent_id = v.agent_id
  JOIN advisories a ON a.advisory_id = v.advisory_id
  LEFT JOIN vulnerability_triage t ON t.agent_id = v.agent_id AND t.advisory_id = v.advisory_id
  WHERE v.advisory_id = ANY($3::text[])
  UNION ALL
  SELECT hp.agent_id, vv.advisory_id, a.os_id, a.os_version, 'open', NULL, NULL,
         jsonb_agg(DISTINCT jsonb_build_object('name', vv.package, 'installed', {INSTALLED}, 'fixed', NULL)),
         false, false, NULL, NULL, NULL, a.source, false
  FROM version_vulnerabilities vv JOIN advisories a ON a.advisory_id = vv.advisory_id
  JOIN host_packages hp ON hp.package_version_id = vv.package_version_id
  JOIN hosts h ON h.agent_id = hp.agent_id AND h.os_id = a.os_id AND h.os_release = a.os_version
  JOIN package_versions pv ON pv.id = vv.package_version_id
  WHERE vv.advisory_id = ANY($3::text[])
    AND NOT EXISTS (SELECT 1 FROM vulnerabilities v WHERE v.agent_id = hp.agent_id
                      AND v.advisory_id = vv.advisory_id AND v.fixed_at IS NULL)
  GROUP BY hp.agent_id, vv.advisory_id, a.os_id, a.os_version, a.source
  UNION ALL
  SELECT hp.agent_id, 'CPE:' || f.cve_id || ':' || f.product, h.os_id, h.os_release, 'open', NULL, NULL,
         jsonb_agg(DISTINCT jsonb_build_object('name', f.package, 'installed', f.installed, 'fixed', NULL)),
         false, max(f.confidence) < 80, max(f.cvss), max(f.confidence)::int, min(f.basis), 'cpe', false
  FROM cpe_findings f JOIN host_packages hp ON hp.package_version_id = f.package_version_id
  JOIN hosts h ON h.agent_id = hp.agent_id AND h.os_release = f.os_version
  WHERE f.cve_id = $4::text
  GROUP BY hp.agent_id, f.cve_id, f.product, h.os_id, h.os_release),
pairs AS MATERIALIZED (
  SELECT * FROM pairs0 WHERE lc = NOT EXISTS (SELECT 1 FROM pairs0 WHERE NOT lc))"
    )
}

/// The summary as one JSON object (`$1`–`$5` as [`pairs`]): counts, the
/// agents in reach, names and fixed versions, people on open pairs, the
/// covering advisories per distribution, each distribution's hosts still
/// affected, confidence inputs, sibling CVEs, the CVE's enrichment and the
/// last 50 triage changes.
pub(crate) fn summary() -> String {
    format!(
        "WITH {pairs},
pk AS (SELECT p.advisory_id, p.os_id, p.os_version, e ->> 'name' AS name, e ->> 'fixed' AS fixed
       FROM pairs p CROSS JOIN jsonb_array_elements(p.packages) e),
adv AS (
  SELECT p.advisory_id AS id, p.os_id, p.os_version, count(*) AS n, a.url, a.title, a.severity,
         (extract(epoch FROM a.issued_at) * 1000)::bigint AS issued, COALESCE(a.source, 'cpe') AS source,
         max(p.cvss) AS cvss, bool_or(p.reboot) AS reboot
  FROM pairs p LEFT JOIN advisories a ON a.advisory_id = p.advisory_id
  GROUP BY p.advisory_id, p.os_id, p.os_version, a.url, a.title, a.severity, a.issued_at, a.source),
dist AS (
  SELECT p.os_id, p.os_version, count(DISTINCT p.agent_id) FILTER (WHERE p.state <> 'resolved') AS hosts,
         bool_or(p.reboot) AS reboot
  FROM pairs p GROUP BY p.os_id, p.os_version)
SELECT jsonb_build_object(
  'open', (SELECT count(*) FILTER (WHERE state = 'open') FROM pairs),
  'total', (SELECT count(*) FROM pairs),
  'agents', (SELECT COALESCE(jsonb_agg(DISTINCT agent_id), '[]') FROM pairs),
  'names', (SELECT COALESCE(jsonb_agg(DISTINCT name), '[]') FROM pk WHERE name IS NOT NULL),
  'fixed', (SELECT COALESCE(jsonb_agg(DISTINCT fixed), '[]') FROM pk WHERE fixed IS NOT NULL),
  'packages', (SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_array(advisory_id, os_id, os_version, name, fixed)), '[]')
               FROM pk WHERE name IS NOT NULL),
  'people', (SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_array(u.user_id::text, u.display_name)), '[]')
             FROM pairs p JOIN console_users u ON u.user_id = p.assignee WHERE p.state = 'open'),
  'advisories', (SELECT COALESCE(jsonb_agg(to_jsonb(adv)), '[]') FROM adv),
  'dists', (SELECT COALESCE(jsonb_agg(to_jsonb(dist)), '[]') FROM dist),
  'confidence', (SELECT COALESCE(jsonb_agg(DISTINCT jsonb_build_array(source, fixable, confidence, basis)), '[]')
                 FROM pairs),
  'also', to_jsonb(ARRAY(SELECT DISTINCT ac.cve_id FROM advisory_cves ac
                         WHERE ac.advisory_id IN (SELECT advisory_id FROM pairs)
                           AND ac.cve_id IS DISTINCT FROM $4::text ORDER BY 1 LIMIT 100)),
  'enrichment', (SELECT jsonb_build_object('kev_due', x.kev_due::text, 'ransomware', x.kev_ransomware,
                          'epss', x.epss, 'epss_percentile', x.epss_percentile, 'cvss', x.cvss_score,
                          'cvss_version', x.cvss_version, 'cvss_vector', x.cvss_vector, 'cwe', x.cwe,
                          'description', x.description)
                 FROM cve_enrichment x WHERE x.cve_id = $4::text),
  'history', (SELECT COALESCE(jsonb_agg(to_jsonb(e) ORDER BY e.at DESC, e.event_id DESC), '[]') FROM (
                SELECT h.event_id, (extract(epoch FROM h.changed_at) * 1000)::bigint AS at,
                       COALESCE(u.display_name, h.changed_by) AS actor, h.agent_id, ho.hostname, h.advisory_id,
                       h.from_state, h.to_state, h.note
                FROM vulnerability_triage_history h JOIN hosts ho ON ho.agent_id = h.agent_id
                LEFT JOIN console_users u ON u.user_id::text = h.changed_by
                WHERE h.advisory_id = ANY($3::text[])
                ORDER BY h.changed_at DESC, h.event_id DESC LIMIT 50) e))",
        pairs = pairs()
    )
}

/// The Hosts table (`$1`–`$5` as [`pairs`], `$6` segment, `$7` limit, `$8`
/// offset): the segment counts as JSON on every row, then the page by host
/// name and agent id; an empty page is one row with the counts only.
pub(crate) fn hosts() -> String {
    format!(
        "WITH {pairs},
seg AS (SELECT p.*, CASE p.state WHEN 'open' THEN 'open' WHEN 'mitigated' THEN 'mitigated' ELSE 'resolved' END AS seg
        FROM pairs p),
counts AS (SELECT jsonb_build_object('all', count(*), 'open', count(*) FILTER (WHERE seg = 'open'),
                    'mitigated', count(*) FILTER (WHERE seg = 'mitigated'),
                    'resolved', count(*) FILTER (WHERE seg = 'resolved')) AS c FROM seg),
page AS (
  SELECT s.*, h.hostname, h.os, h.address,
         row_number() OVER (ORDER BY h.hostname, s.agent_id, s.advisory_id, s.state) AS ord
  FROM seg s JOIN hosts h ON h.agent_id = s.agent_id
  WHERE $6::text = 'all' OR s.seg = $6::text
  ORDER BY ord LIMIT $7 OFFSET $8)
SELECT c.c, p.agent_id, p.hostname, p.os, p.address,
       (SELECT string_agg(DISTINCT e ->> 'installed', ', ') FROM jsonb_array_elements(p.packages) e),
       p.state, p.assignee::text, u.display_name, p.advisory_id, p.version
FROM counts c LEFT JOIN page p ON true
LEFT JOIN console_users u ON u.user_id = p.assignee
ORDER BY p.ord",
        pairs = pairs()
    )
}

/// How many pairs (`$1`–`$5` as [`pairs`]).
fn count_sql() -> String {
    format!("WITH {} SELECT count(*) FROM pairs", pairs())
}

/// Other keys in reach (`$1`, `$2`) on the package names `$3`, but `$4`:
/// rows per worst advisory severity.
pub(crate) fn same_package() -> String {
    let visible = agent_visibility("a.agent_id", "$1", "$2");
    format!(
        "WITH hosts AS MATERIALIZED (SELECT a.agent_id, a.os_id, a.os_release FROM agents a WHERE {visible}),
cand AS (SELECT DISTINCT ap.advisory_id FROM advisory_packages ap WHERE ap.name = ANY($3::text[])),
reach AS (
  SELECT c.advisory_id FROM cand c JOIN advisories a ON a.advisory_id = c.advisory_id
  WHERE EXISTS (SELECT 1 FROM vulnerabilities v JOIN hosts h ON h.agent_id = v.agent_id
                WHERE v.advisory_id = c.advisory_id)
     OR EXISTS (SELECT 1 FROM version_vulnerabilities vv
                JOIN host_packages hp ON hp.package_version_id = vv.package_version_id
                JOIN hosts h ON h.agent_id = hp.agent_id AND h.os_id = a.os_id AND h.os_release = a.os_version
                WHERE vv.advisory_id = c.advisory_id)),
keys AS (
  SELECT COALESCE(ac.cve_id, r.advisory_id) AS key,
         min(array_position({SEVERITIES}, a.severity)) AS sev
  FROM reach r JOIN advisories a ON a.advisory_id = r.advisory_id
  LEFT JOIN advisory_cves ac ON ac.advisory_id = r.advisory_id
  GROUP BY 1)
SELECT ({SEVERITIES})[sev], count(*) FROM keys WHERE key <> $4::text GROUP BY sev ORDER BY sev",
        SEVERITIES = crate::vuln_list_sql::SEVERITIES
    )
}

/// The pairs' advisories and CVE.
pub(crate) struct Target {
    /// The canonical key.
    pub key: String,
    /// The advisories naming it.
    pub advisories: Vec<String>,
    /// The CVE, for CPE matches.
    pub cve: Option<String>,
}

async fn count(
    client: &Client,
    scope: &AgentScope,
    t: &Target,
    today: NaiveDate,
) -> Result<i64, StoreError> {
    Ok(client
        .query_one(
            &count_sql(),
            &[
                &scope.is_global(),
                &scope.group_ids(),
                &t.advisories,
                &t.cve,
                &today,
            ],
        )
        .await?
        .get(0))
}

/// Resolves `key` (ruling 7): a CVE; an advisory with one CVE as that CVE;
/// one with none as itself; one with several as [`Lookup::SeveralCves`]
/// when a pair is in reach. A CPE match key is not a page.
pub(crate) async fn resolve(
    client: &Client,
    key: &str,
    scope: &AgentScope,
    today: NaiveDate,
) -> Result<Lookup<Target>, StoreError> {
    if key.is_empty() || key.starts_with("CPE:") {
        return Ok(Lookup::Missing);
    }
    let mut key = key.to_owned();
    loop {
        let r = client
            .query_one(
                "SELECT ARRAY(SELECT advisory_id FROM advisory_cves WHERE cve_id = $1 ORDER BY 1),
                        EXISTS (SELECT 1 FROM advisories WHERE advisory_id = $1),
                        ARRAY(SELECT cve_id FROM advisory_cves WHERE advisory_id = $1 ORDER BY 1)",
                &[&key],
            )
            .await?;
        let (naming, advisory, mut cves): (Vec<String>, bool, Vec<String>) =
            (r.get(0), r.get(1), r.get(2));
        let t = if !naming.is_empty() || !advisory {
            Target {
                cve: Some(key.clone()),
                key,
                advisories: naming,
            }
        } else if cves.len() == 1 {
            key = cves.remove(0);
            continue;
        } else {
            let t = Target {
                advisories: vec![key.clone()],
                key,
                cve: None,
            };
            if cves.len() > 1 {
                return Ok(if count(client, scope, &t, today).await? > 0 {
                    Lookup::SeveralCves(cves)
                } else {
                    Lookup::Missing
                });
            }
            t
        };
        return Ok(Lookup::Found(t));
    }
}
