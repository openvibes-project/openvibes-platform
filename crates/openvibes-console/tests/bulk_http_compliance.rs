//! Bulk triage over HTTP (triage v2): cases, vulnerability triage and
//! Compliance check rows.

use axum::http::StatusCode;
use serde_json::json;

mod common;
use common::bulk::*;

#[tokio::test]
async fn items_go_into_one_open_case_and_vulnerabilities_triage_per_host() {
    let (db, router, ids) = setup().await;
    let (cookie, csrf) = login(&router, "alice").await;
    let items = json!(
        ids.iter()
            .map(|id| json!({"id": id.to_string()}))
            .collect::<Vec<_>>()
    );
    let first = json!({"action": "case", "new_case_title": "2 alarms: test", "new_case_severity": "high", "items": items});
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(first),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["changed"].as_u64(), Some(2));
    assert!(body["case_number"].as_i64().is_some());
    // The lists' case badges: both alarms, under that case's number.
    let (_, active, _) = call(
        &router,
        "GET",
        "/api/v1/cases/active-items?kind=alarm",
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    let refs: Vec<&str> = active["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["ref"].as_str().unwrap())
        .collect();
    assert_eq!(refs.len(), 2, "{active}");
    assert!(
        active["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["case_number"] == body["case_number"])
    );
    let second = json!({"action": "case", "new_case_title": "again", "items": items});
    let (_, body, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(second),
        None,
    )
    .await;
    assert_eq!(body["changed"].as_u64(), Some(0));
    assert!(
        body["skipped"]
            .as_array()
            .unwrap()
            .iter()
            .all(|s| s["reason"] == "in another open case")
    );
    // and no empty case was opened for them.
    assert!(body["case_number"].is_null(), "{body}");
    // An advisory expands to both hosts.
    let vulns = json!({"action": "state", "state": "false_positive", "note": "not affected", "items": [{"advisory_id": "FEDORA-1"}]});
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/vulnerabilities/bulk",
        &cookie,
        &csrf,
        Some(vulns),
        None,
    )
    .await;
    assert_eq!(
        (status, body["changed"].as_u64()),
        (StatusCode::OK, Some(2)),
        "{body}"
    );
    // One host, version-checked; the list shows the state.
    let one = format!("/api/v1/vulnerabilities/advisories/FEDORA-1/hosts/{WEB}/triage");
    let reopen = json!({"state": "open"});
    // WEB is at version 1 after the bulk change: 0 is stale.
    let (status, _, _) = call(
        &router,
        "PUT",
        &one,
        &cookie,
        &csrf,
        Some(reopen.clone()),
        Some("\"0\""),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::PRECONDITION_FAILED,
        "version 1 is current"
    );
    let (status, saved, etag) = call(
        &router,
        "PUT",
        &one,
        &cookie,
        &csrf,
        Some(reopen),
        Some("\"1\""),
    )
    .await;
    assert_eq!(
        (status, saved["state"].as_str(), etag.as_deref()),
        (StatusCode::OK, Some("open"), Some("\"2\""))
    );
    // A vulnerability never triaged is version 0, and that is accepted.
    let first = format!("/api/v1/vulnerabilities/advisories/FEDORA-2/hosts/{WEB}/triage");
    let accept = json!({"state": "mitigated", "note": "compensating control"});
    let (status, saved, _) = call(
        &router,
        "PUT",
        &first,
        &cookie,
        &csrf,
        Some(accept),
        Some("\"0\""),
    )
    .await;
    assert_eq!(
        (status, saved["version"].as_i64()),
        (StatusCode::OK, Some(1)),
        "{saved}"
    );
    let (_, list, _) = call(
        &router,
        "GET",
        "/api/v1/vulnerabilities?advisory=FEDORA-1",
        &cookie,
        &csrf,
        None,
        None,
    )
    .await;
    let states: Vec<&str> = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["triage_state"].as_str().unwrap())
        .collect();
    assert_eq!(states.len(), 2);
    assert!(
        states.contains(&"open") && states.contains(&"false_positive"),
        "{states:?}"
    );
    // A CVE row's bulk close changes the open host only; the false positive
    // is not reached (closed pairs are not part of the action).
    let close = json!({"action": "state", "state": "mitigated", "note": "patched", "items": [{"advisory_id": "FEDORA-1"}]});
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/vulnerabilities/bulk",
        &cookie,
        &csrf,
        Some(close),
        None,
    )
    .await;
    assert_eq!(
        (status, body["changed"].as_u64()),
        (StatusCode::OK, Some(1)),
        "{body}"
    );
    assert_eq!(body["skipped"].as_array().unwrap().len(), 0, "{body}");
    // A list row on the Host chip names its host and says `open_only`: web's
    // mitigated FEDORA-2 pair is left alone, as on every host.
    let row = json!({"action": "state", "state": "false_positive", "note": "lab",
        "items": [{"advisory_id": "FEDORA-2", "agent_id": WEB, "open_only": true}]});
    let (status, body, _) = call(
        &router,
        "POST",
        "/api/v1/vulnerabilities/bulk",
        &cookie,
        &csrf,
        Some(row),
        None,
    )
    .await;
    assert_eq!(
        (status, body["changed"].as_u64()),
        (StatusCode::OK, Some(0)),
        "{body}"
    );
    assert_eq!(
        body["skipped"][0]["id"],
        format!("{WEB}/FEDORA-2"),
        "{body}"
    );
    assert_eq!(body["skipped"][0]["reason"], "not open", "{body}");
    // `open_only` belongs to vulnerability and compliance items only.
    let wrong =
        json!({"action": "assign", "assignee": null, "items": [{"id": "1", "open_only": true}]});
    let (status, _, _) = call(
        &router,
        "POST",
        "/api/v1/alarms/bulk",
        &cookie,
        &csrf,
        Some(wrong),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    db.drop().await;
}

/// A Compliance list row (one check) closes only its open, failing pairs, with
/// or without the Host chip; `open_only` stays refused on alarm items.
#[tokio::test]
async fn compliance_rows_close_only_open_failing_pairs() {
    let (db, router, _) = setup().await;
    db.pool
        .get()
        .await
        .unwrap()
        .batch_execute(&format!(
            "INSERT INTO current_findings (agent_id, rule_set_id, rule_id, last_finding_id, rule_version,
                severity, first_observed_at, last_observed_at, last_observed_day, scan_id, confidence,
                message, evidence, received_at, origin, authenticated, ended_at)
             VALUES ('{WEB}', 'baseline', 'ssh', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, NULL),
                    ('{DB}', 'baseline', 'ssh', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, now() - interval '1 hour'),
                    ('{WEB}', 'baseline', 'telnet', 'f', 1, 'low', now(), now(), current_date, 's', 90, 'm', '{{}}', now(), 'online', true, NULL);
             INSERT INTO console_finding_triage (agent_id, rule_set_id, rule_id, state, rule_version, note,
                version, updated_at, updated_by)
             VALUES ('{WEB}', 'baseline', 'telnet', 'mitigated', 1, 'n', 1, now(), 't');"
        ))
        .await
        .unwrap();
    let (cookie, csrf) = login(&router, "alice").await;
    let post = |path: &'static str, body: serde_json::Value| {
        let (router, cookie, csrf) = (router.clone(), cookie.clone(), csrf.clone());
        async move {
            let (status, body, _) =
                call(&router, "POST", path, &cookie, &csrf, Some(body), None).await;
            (status, body)
        }
    };
    let close = |items: serde_json::Value| json!({"action": "state", "state": "mitigated", "note": "fixed", "items": items});
    // The check's row, no Host chip: web's failing pair only; db's ended one
    // is not expanded.
    let (status, body) = post(
        "/api/v1/compliance/bulk",
        close(json!([{"rule_set_id": "baseline", "rule_id": "ssh", "open_only": true}])),
    )
    .await;
    assert_eq!(
        (status, body["changed"].as_u64()),
        (StatusCode::OK, Some(1)),
        "{body}"
    );
    assert_eq!(body["skipped"].as_array().unwrap().len(), 0, "{body}");
    // With the Host chip: web's mitigated telnet pair is left alone.
    let (status, body) = post(
        "/api/v1/compliance/bulk",
        close(json!([{"rule_set_id": "baseline", "rule_id": "telnet", "agent_id": WEB, "open_only": true}])),
    )
    .await;
    assert_eq!(
        (status, body["changed"].as_u64()),
        (StatusCode::OK, Some(0)),
        "{body}"
    );
    assert_eq!(
        body["skipped"][0]["id"],
        format!("{WEB}/baseline/telnet"),
        "{body}"
    );
    assert_eq!(body["skipped"][0]["reason"], "not open", "{body}");
    // Add to case from the row: web's failing pair goes in (closed or not);
    // db's ended one never does.
    let (status, body) = post(
        "/api/v1/compliance/bulk",
        json!({"action": "case", "new_case_title": "ssh", "items": [{"rule_set_id": "baseline", "rule_id": "ssh"}]}),
    )
    .await;
    assert_eq!(
        (status, body["changed"].as_u64()),
        (StatusCode::OK, Some(1)),
        "{body}"
    );
    assert_eq!(body["skipped"].as_array().unwrap().len(), 0, "{body}");
    // Not for alarm items.
    let (status, _) = post(
        "/api/v1/alarms/bulk",
        json!({"action": "assign", "assignee": null, "items": [{"id": "1", "open_only": true}]}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    db.drop().await;
}
