//! Cases over HTTP, a case's life: opened, read, changed, noted and closed
//! with versions and audit, and the closing note.
//! Shared harness: `common/cases.rs`.

mod common;
use common::cases::*;

#[tokio::test]
async fn a_case_is_opened_read_changed_noted_and_closed_with_versions_and_audit() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let finding = format!("{WEB}/baseline/ssh-root");
    let (status, created, etag) = fx
        .send(
            &alice,
            "POST",
            "/api/v1/cases",
            Some(json!({
                "title": "  SSH on web-01  ",
                "assignee_user_id": DAVE.to_uppercase(),
                "items": [
                    {"kind": "host", "ref": WEB},
                    {"kind": "compliance_finding", "ref": finding},
                    {"kind": "alarm", "ref": fx.web_alarm},
                ]
            })),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_eq!(etag.as_deref(), Some("\"1\""));
    assert_eq!(created["title"], "SSH on web-01");
    assert_eq!(created["status"], "open");
    assert_eq!(created["severity"], "high", "highest item severity");
    assert_eq!(created["assignee"]["username"], "dave");
    assert_eq!(created["opened_by"]["username"], "alice");
    assert_eq!(
        (
            created["item_count"].clone(),
            created["pending_item_count"].clone()
        ),
        (json!(3), json!(2))
    );
    assert!(created["number"].as_i64().unwrap() > 0);
    assert_eq!(created["resolution"], Value::Null);
    let host = item_of(&created, "host");
    assert_eq!(host["ref"], WEB);
    assert_eq!(host["hostname"], "web-01");
    assert_eq!(host["title"], "web-01");
    assert_eq!(host["active"], true);
    let finding_item = item_of(&created, "compliance_finding");
    assert_eq!(finding_item["title"], "Root login over SSH");
    assert_eq!(finding_item["evidence_gone"], false);
    assert_eq!(created["events"][0]["kind"], "created");
    assert_eq!(created["events"][0]["actor"]["username"], "alice");
    let uri = case_uri(&created);

    // Read it back, as another analyst.
    let dave = fx.session("dave").await;
    let (status, read, etag) = fx.send(&dave, "GET", &uri, None, None).await;
    assert_eq!((status, etag.as_deref()), (StatusCode::OK, Some("\"1\"")));
    assert_eq!(read["case_id"], created["case_id"]);
    let (_, page) = fx.get(&dave, "/api/v1/cases?assignee=me").await;
    assert_eq!(page["items"][0]["case_id"], created["case_id"]);
    assert_eq!(
        page["items"][0].get("items"),
        None,
        "the list has counts, not items"
    );

    // A note goes on the timeline; the case moves on.
    let secret = "the admin password is hunter2";
    let (status, note, _) = fx
        .send(
            &dave,
            "POST",
            &format!("{uri}/notes"),
            Some(json!({"body": secret})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{note}");
    assert_eq!(
        (note["kind"].clone(), note["body"].clone()),
        (json!("note"), json!(secret))
    );
    assert_eq!(note["actor"]["username"], "dave");

    // Changing it needs the version.
    let body = put_body(
        &read,
        json!({"status": "investigating", "title": "SSH root login"}),
    );
    let (status, problem, _) = fx.send(&dave, "PUT", &uri, Some(body.clone()), None).await;
    assert_eq!(
        (status, problem["code"].clone()),
        (
            StatusCode::PRECONDITION_REQUIRED,
            json!("precondition_required")
        )
    );
    let (status, problem, _) = fx
        .send(&dave, "PUT", &uri, Some(body.clone()), Some("1"))
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::BAD_REQUEST, json!("invalid_precondition"))
    );
    let (status, saved, etag) = fx
        .send(&dave, "PUT", &uri, Some(body.clone()), Some("\"1\""))
        .await;
    assert_eq!(status, StatusCode::OK, "{saved}");
    assert_eq!(
        (saved["status"].clone(), saved["title"].clone()),
        (json!("investigating"), json!("SSH root login"))
    );
    assert_eq!(etag.as_deref(), Some("\"2\""));
    let (status, problem, _) = fx
        .send(&alice, "PUT", &uri, Some(body), Some("\"1\""))
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::PRECONDITION_FAILED, json!("stale_case"))
    );

    // Closing needs outcomes first.
    let close = put_body(
        &saved,
        json!({"status": "closed", "closing_note": "Disabled root login"}),
    );
    let (status, problem, _) = fx
        .send(&alice, "PUT", &uri, Some(close.clone()), Some("\"2\""))
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("items_unresolved"))
    );
    for kind in ["compliance_finding", "alarm"] {
        let item = item_of(&saved, kind)["item_id"].as_str().unwrap();
        let (status, set, _) = fx
            .send(
                &alice,
                "PUT",
                &format!("{uri}/items/{item}/outcome"),
                Some(json!({"outcome": "false_positive", "note": "Expected for this host"})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{set}");
        assert_eq!(set["outcome"], "false_positive");
    }
    let (status, closed, etag) = fx
        .send(&alice, "PUT", &uri, Some(close), Some("\"2\""))
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(etag.as_deref(), Some("\"3\""));
    assert_eq!(closed["status"], "closed");
    assert_eq!(closed["resolution"], Value::Null, "new closes set none");
    assert_eq!(closed["resolution_note"], "Disabled root login");
    assert!(closed["closed_at"].is_string());
    assert!(
        closed["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["active"] == false)
    );
    let kinds: Vec<_> = closed["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        kinds,
        [
            "created",
            "assigned",
            "item_added",
            "item_added",
            "item_added",
            "note",
            "status",
            "item_outcome",
            "item_outcome",
            "resolved"
        ]
    );

    // The audit log says what happened and never what was written.
    let audit = fx.audit().await;
    let actions: Vec<_> = audit.iter().map(|(a, _)| a.as_str()).collect();
    assert_eq!(
        actions,
        [
            "case.create",
            "case.item.add",
            "case.item.add",
            "case.item.add",
            "case.note",
            "case.update",
            "case.item.outcome",
            "case.item.outcome",
            "case.close"
        ]
    );
    assert!(
        audit.iter().all(|(_, detail)| !detail.contains("hunter2")),
        "{audit:?}"
    );
    fx.db.drop().await;
}

#[tokio::test]
async fn closing_is_refused_without_a_closing_note() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let case = fx
        .open(&alice, "Closing", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let uri = case_uri(&case);
    let tomorrow = (Utc::now() + chrono::Duration::days(1)).to_rfc3339();
    // Step 5d: closing takes a closing note only.
    for (changes, field, code) in [
        (
            json!({"status": "closed"}),
            "closing_note",
            "closing_note_required",
        ),
        (
            json!({"status": "closed", "closing_note": "   "}),
            "closing_note",
            "closing_note_required",
        ),
        (
            json!({"status": "open", "closing_note": "x"}),
            "closing_note",
            "closing_note_not_allowed",
        ),
        (json!({"status": "done"}), "status", "invalid_status"),
        (
            json!({"severity": "urgent"}),
            "severity",
            "invalid_severity",
        ),
        (json!({"title": ""}), "title", "invalid_title"),
        (json!({"title": "t".repeat(121)}), "title", "invalid_title"),
    ] {
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &uri,
                Some(put_body(&case, changes.clone())),
                Some(&version(&case)),
            )
            .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{changes}: {problem}"
        );
        assert_eq!(problem["code"], "invalid_case");
        assert_eq!(
            field_errors(&problem),
            [(field.to_owned(), code.to_owned())],
            "{changes}"
        );
    }
    // None of that changed the case.
    let (_, same) = fx.get(&alice, &uri).await;
    assert_eq!(
        (same["version"].clone(), same["status"].clone()),
        (json!(1), json!("open"))
    );
    // The case-level resolution and date are gone: naming one is refused.
    for (field, value) in [
        ("resolution", json!("accepted_risk")),
        ("accepted_until", json!(tomorrow)),
    ] {
        let mut changes = json!({"status": "closed", "closing_note": "Until the rebuild"});
        changes[field] = value;
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &uri,
                Some(put_body(&case, changes)),
                Some("\"1\""),
            )
            .await;
        assert_eq!(
            (status, problem["code"].clone()),
            (StatusCode::BAD_REQUEST, json!("invalid_request")),
            "{field}"
        );
        assert_eq!(problem["field_errors"][0]["field"], field);
    }
    // `null` for either is as good as leaving it out.
    let (status, closed, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(&case, json!({"status": "closed", "closing_note": "Until the rebuild", "resolution": null, "accepted_until": null}))),
            Some("\"1\""),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    assert_eq!(closed["resolution_note"], "Until the rebuild");
    assert_eq!(
        (
            closed["resolution"].clone(),
            closed["accepted_until"].clone()
        ),
        (Value::Null, Value::Null)
    );
    // A closed case keeps its note, takes no items and no outcomes.
    let (status, problem, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(
                &closed,
                json!({"status": "closed", "closing_note": "Changed"}),
            )),
            Some(&version(&closed)),
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("case_closed"))
    );
    let (status, problem, _) = fx
        .send(
            &alice,
            "POST",
            &format!("{uri}/items"),
            Some(json!({"kind": "host", "ref": DB})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("case_closed"))
    );
    let host = closed["items"][0]["item_id"].as_str().unwrap();
    let (status, problem, _) = fx
        .send(&alice, "DELETE", &format!("{uri}/items/{host}"), None, None)
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("case_closed"))
    );
    // Reopening clears the resolution.
    let (status, reopened, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(&closed, json!({"status": "investigating"}))),
            Some(&version(&closed)),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{reopened}");
    assert_eq!(
        (
            reopened["resolution"].clone(),
            reopened["accepted_until"].clone(),
            reopened["closed_at"].clone()
        ),
        (Value::Null, Value::Null, Value::Null)
    );
    assert!(reopened["items"][0]["active"].as_bool().unwrap());
    fx.db.drop().await;
}
