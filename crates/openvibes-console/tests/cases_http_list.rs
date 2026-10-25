//! Cases over HTTP, scope and the list: a scoped user's view and adds,
//! validation, paging and filters.
//! Shared harness: `common/cases.rs`.

mod common;
use common::cases::*;

#[tokio::test]
async fn a_scoped_user_sees_and_adds_only_what_is_in_scope() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let bob = fx.session("bob").await;
    let mixed = fx
        .open(
            &alice,
            "Mixed",
            json!([
                {"kind": "host", "ref": WEB},
                {"kind": "host", "ref": DB},
                {"kind": "alarm", "ref": fx.db_alarm},
            ]),
        )
        .await;
    let only_db = fx
        .open(&alice, "Only db-01", json!([{"kind": "host", "ref": DB}, {"kind": "compliance_finding", "ref": format!("{DB}/baseline/ssh-root")}]))
        .await;
    // Bob sees the mixed case without the db-01 items, in counts too.
    let (status, seen) = fx.get(&bob, &case_uri(&mixed)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(seen["items"].as_array().unwrap().len(), 1);
    assert_eq!(seen["items"][0]["ref"], WEB);
    assert_eq!(seen["item_count"], 1);
    assert_eq!(
        seen["pending_item_count"], 0,
        "the hidden alarm is not counted"
    );
    let rendered = seen.to_string();
    assert!(!rendered.contains(DB), "{rendered}");
    assert!(
        seen["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["kind"] != "alarm")
    );
    let kinds: Vec<_> = seen["events"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["created", "item_added"], "only the item he can see");
    // The other case does not exist for him: not in the list, not by id, not by search.
    let (_, page) = fx.get(&bob, "/api/v1/cases?status=all").await;
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    let (_, found) = fx
        .get(&bob, &format!("/api/v1/cases?q=C-{}", only_db["number"]))
        .await;
    assert!(found["items"].as_array().unwrap().is_empty());
    let hidden = case_uri(&only_db);
    let (status, problem) = fx.get(&bob, &hidden).await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::NOT_FOUND, json!("case_not_found"))
    );
    let unknown = fx
        .get(&bob, "/api/v1/cases/00000000-0000-4000-8000-000000000000")
        .await;
    assert_eq!(unknown.0, StatusCode::NOT_FOUND);
    assert_eq!(
        unknown.1["code"], problem["code"],
        "same answer for an absent and a hidden case"
    );
    let item = only_db["items"][0]["item_id"].as_str().unwrap();
    for (method, uri, body, if_match) in [
        (
            "PUT",
            hidden.clone(),
            Some(put_body(&only_db, json!({"title": "Mine"}))),
            Some("\"1\""),
        ),
        (
            "POST",
            format!("{hidden}/notes"),
            Some(json!({"body": "hello"})),
            None,
        ),
        (
            "POST",
            format!("{hidden}/items"),
            Some(json!({"kind": "host", "ref": WEB})),
            None,
        ),
        ("DELETE", format!("{hidden}/items/{item}"), None, None),
        (
            "PUT",
            format!("{hidden}/items/{item}/outcome"),
            Some(json!({"outcome": "false_positive", "note": "x"})),
            None,
        ),
    ] {
        let (status, problem, _) = fx.send(&bob, method, &uri, body, if_match).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{method} {uri}: {problem}");
        assert_eq!(problem["code"], "case_not_found", "404, never 403");
    }
    // He cannot add what is out of scope, and a missing object looks the same.
    let bobs = fx
        .open(&bob, "Bob's case", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let bobs_uri = case_uri(&bobs);
    let missing_host = format!("{DB}x");
    for (kind, reference) in [
        ("host", DB),
        ("alarm", fx.db_alarm.as_str()),
        ("compliance_finding", &format!("{DB}/baseline/ssh-root")),
        ("vulnerability", &format!("{DB}/FEDORA-1")),
        ("software", "rpm/bash"),
        ("host", &missing_host),
        ("alarm", "999999"),
    ] {
        let (status, problem, _) = fx
            .send(
                &bob,
                "POST",
                &format!("{bobs_uri}/items"),
                Some(json!({"kind": kind, "ref": reference})),
                None,
            )
            .await;
        assert_eq!(
            status,
            StatusCode::NOT_FOUND,
            "{kind} {reference}: {problem}"
        );
        assert_eq!(problem["code"], "item_not_found");
    }
    let (status, problem, _) = fx
        .send(
            &bob,
            "POST",
            "/api/v1/cases",
            Some(json!({"title": "No", "items": [{"kind": "host", "ref": DB}]})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::NOT_FOUND, json!("item_not_found"))
    );
    // His own are fine.
    let (status, added, _) = fx
        .send(
            &bob,
            "POST",
            &format!("{bobs_uri}/items"),
            Some(json!({"kind": "software", "ref": "rpm/openssl"})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    // Closing with items he cannot see is refused, without saying what.
    let (status, problem, _) = fx
        .send(
            &bob,
            "PUT",
            &case_uri(&mixed),
            Some(put_body(
                &seen,
                json!({"status": "closed", "closing_note": "Done"}),
            )),
            Some(&version(&seen)),
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("hidden_items_unresolved"))
    );
    // for-item never reveals a case he cannot see.
    let (_, found) = fx
        .get(&bob, &format!("/api/v1/cases/for-item?kind=host&ref={DB}"))
        .await;
    assert!(found["items"].as_array().unwrap().is_empty());
    // Someone assigned to a case sees it, with only the items they may.
    let (status, assigned, _) = fx
        .send(
            &alice,
            "PUT",
            &hidden,
            Some(put_body(&only_db, json!({"assignee_user_id": BOB}))),
            Some("\"1\""),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{assigned}");
    let (status, as_assignee) = fx.get(&bob, &hidden).await;
    assert_eq!(status, StatusCode::OK);
    assert!(as_assignee["items"].as_array().unwrap().is_empty());
    fx.db.drop().await;
}

#[tokio::test]
async fn requests_are_validated_and_the_list_pages_and_filters() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    // Bad bodies.
    for body in [
        json!({}),
        json!({"title": 5}),
        json!({"title": "x", "surprise": true}),
        json!({"title": "x", "items": "all"}),
        json!({"title": "x", "items": [{"kind": "host"}]}),
    ] {
        let (status, problem, _) = fx
            .send(&alice, "POST", "/api/v1/cases", Some(body.clone()), None)
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}: {problem}");
        assert_eq!(problem["code"], "invalid_request");
    }
    for (body, field, code) in [
        (json!({"title": ""}), "title", "invalid_title"),
        (json!({"title": "t".repeat(121)}), "title", "invalid_title"),
        (
            json!({"title": "x", "severity": "urgent"}),
            "severity",
            "invalid_severity",
        ),
        (
            json!({"title": "x", "items": [{"kind": "port", "ref": "tcp/22"}]}),
            "kind",
            "invalid_kind",
        ),
        (
            json!({"title": "x", "items": [{"kind": "alarm", "ref": "04"}]}),
            "ref",
            "invalid_ref",
        ),
        (
            json!({"title": "x", "items": (0..51).map(|n| json!({"kind": "software", "ref": format!("rpm/p{n}")})).collect::<Vec<_>>()}),
            "items",
            "too_many_items",
        ),
    ] {
        let (status, problem, _) = fx
            .send(&alice, "POST", "/api/v1/cases", Some(body.clone()), None)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
        assert_eq!(
            field_errors(&problem),
            [(field.to_owned(), code.to_owned())],
            "{body}"
        );
    }
    // Notes.
    let case = fx
        .open(&alice, "Notes", json!([{"kind": "host", "ref": WEB}]))
        .await;
    let uri = case_uri(&case);
    for body in [
        json!({"body": ""}),
        json!({"body": "   "}),
        json!({"body": "x".repeat(4001)}),
        json!({"body": "bell\u{7}"}),
    ] {
        let (status, problem, _) = fx
            .send(&alice, "POST", &format!("{uri}/notes"), Some(body), None)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    }
    let (status, _, _) = fx
        .send(
            &alice,
            "POST",
            &format!("{uri}/notes"),
            Some(json!({"text": "x"})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Query errors.
    for query in [
        "status=done",
        "severity=urgent",
        "limit=0",
        "limit=101",
        "cursor=garbage",
        "surprise=1",
    ] {
        let (status, problem) = fx.get(&alice, &format!("/api/v1/cases?{query}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}: {problem}");
    }
    for query in ["", "?kind=host", "?ref=x"] {
        let (status, _) = fx
            .get(&alice, &format!("/api/v1/cases/for-item{query}"))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
    }
    let (status, problem) = fx
        .get(&alice, "/api/v1/cases/for-item?kind=port&ref=x")
        .await;
    assert_eq!(
        (status, field_errors(&problem)),
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            vec![("kind".to_owned(), "invalid_kind".to_owned())]
        )
    );

    // Paging and filters over three more cases.
    for (title, severity) in [("Alpha", "low"), ("Bravo", "high"), ("Charlie", "high")] {
        let (status, created, _) = fx
            .send(
                &alice,
                "POST",
                "/api/v1/cases",
                Some(json!({"title": title, "severity": severity, "assignee_user_id": DAVE})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{created}");
    }
    let (_, first) = fx.get(&alice, "/api/v1/cases?limit=2").await;
    let titles: Vec<_> = first["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["Charlie", "Bravo"], "newest change first");
    let cursor = first["next_cursor"].as_str().unwrap();
    let (_, second) = fx
        .get(&alice, &format!("/api/v1/cases?limit=2&cursor={cursor}"))
        .await;
    let titles: Vec<_> = second["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["title"].as_str().unwrap())
        .collect();
    assert_eq!(titles, ["Alpha", "Notes"]);
    assert_eq!(second["next_cursor"], Value::Null);
    let (_, high) = fx
        .get(&alice, "/api/v1/cases?severity=high&assignee=none")
        .await;
    assert!(high["items"].as_array().unwrap().is_empty());
    let (_, high) = fx
        .get(
            &alice,
            &format!("/api/v1/cases?severity=high&assignee={DAVE}"),
        )
        .await;
    assert_eq!(high["items"].as_array().unwrap().len(), 2);
    let (_, found) = fx.get(&alice, "/api/v1/cases?q=brav").await;
    assert_eq!(found["items"][0]["title"], "Bravo");
    let (_, none) = fx.get(&alice, "/api/v1/cases?status=closed").await;
    assert!(none["items"].as_array().unwrap().is_empty());
    fx.db.drop().await;
}
