//! Cases over HTTP, items: exclusive items, removal and assignees.
//! Shared harness: `common/cases.rs`.

mod common;
use common::cases::*;

#[tokio::test]
async fn an_item_cannot_be_in_two_open_cases() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let dave = fx.session("dave").await;
    let finding = format!("{WEB}/baseline/ssh-root");
    let vuln = format!("{WEB}/FEDORA-1");
    let items = json!([
        {"kind": "alarm", "ref": fx.web_alarm},
        {"kind": "compliance_finding", "ref": finding},
        {"kind": "vulnerability", "ref": vuln},
    ]);
    let first = fx.open(&alice, "First", items.clone()).await;
    let number = first["number"].as_i64().unwrap();
    // Creating another case with any of them is refused, naming the first.
    for item in items.as_array().unwrap() {
        let (status, problem, _) = fx
            .send(
                &dave,
                "POST",
                "/api/v1/cases",
                Some(json!({"title": "Second", "items": [item]})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "{problem}");
        assert_eq!(problem["code"], "item_in_case");
        assert_eq!(problem["case_number"], number);
    }
    let (_, page) = fx.get(&dave, "/api/v1/cases?status=all").await;
    assert_eq!(
        page["items"].as_array().unwrap().len(),
        1,
        "the refused creates left nothing behind"
    );
    // So is adding it to an existing case; adding it twice to one is its own error.
    let second = fx.open(&dave, "Second", json!([])).await;
    let second_uri = case_uri(&second);
    let (status, problem, _) = fx
        .send(
            &dave,
            "POST",
            &format!("{second_uri}/items"),
            Some(json!({"kind": "alarm", "ref": fx.web_alarm})),
            None,
        )
        .await;
    assert_eq!(
        (
            status,
            problem["code"].clone(),
            problem["case_number"].clone()
        ),
        (StatusCode::CONFLICT, json!("item_in_case"), json!(number))
    );
    let (status, problem, _) = fx
        .send(
            &alice,
            "POST",
            &format!("{}/items", case_uri(&first)),
            Some(json!({"kind": "alarm", "ref": fx.web_alarm})),
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("item_already_in_case"))
    );
    // The same host can be in both, and the other host's vulnerability is another item.
    for (uri, kind, reference) in [
        (&second_uri, "host", WEB.to_owned()),
        (&case_uri(&first), "host", WEB.to_owned()),
        (&second_uri, "vulnerability", format!("{DB}/FEDORA-1")),
    ] {
        let (status, added, _) = fx
            .send(
                &dave,
                "POST",
                &format!("{uri}/items"),
                Some(json!({"kind": kind, "ref": reference})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "{added}");
    }
    // for-item says where an exclusive item is, and lists a host's cases.
    let (_, found) = fx
        .get(
            &dave,
            &format!("/api/v1/cases/for-item?kind=alarm&ref={}", fx.web_alarm),
        )
        .await;
    assert_eq!(found["items"].as_array().unwrap().len(), 1);
    assert_eq!(found["items"][0]["case"]["number"], number);
    assert_eq!(
        found["items"][0]["item_id"],
        item_of(&first, "alarm")["item_id"]
    );
    let (_, found) = fx
        .get(
            &dave,
            &format!("/api/v1/cases/for-item?kind=host&ref={WEB}"),
        )
        .await;
    assert_eq!(found["items"].as_array().unwrap().len(), 2);
    // Closing the first frees its alarm.
    for kind in ["alarm", "compliance_finding", "vulnerability"] {
        let item = item_of(&first, kind)["item_id"].as_str().unwrap();
        let (status, set, _) = fx
            .send(
                &alice,
                "PUT",
                &format!("{}/items/{item}/outcome", case_uri(&first)),
                Some(json!({"outcome": "false_positive", "note": "ok"})),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{set}");
    }
    let (status, closed, _) = fx
        .send(
            &alice,
            "PUT",
            &case_uri(&first),
            Some(put_body(
                &first,
                json!({"status": "closed", "closing_note": "Known"}),
            )),
            Some("\"1\""),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{closed}");
    let (status, added, _) = fx
        .send(
            &dave,
            "POST",
            &format!("{second_uri}/items"),
            Some(json!({"kind": "alarm", "ref": fx.web_alarm})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::CREATED, "{added}");
    // Reopening the first now conflicts with the second.
    let (status, problem, _) = fx
        .send(
            &alice,
            "PUT",
            &case_uri(&first),
            Some(put_body(&closed, json!({"status": "open"}))),
            Some(&version(&closed)),
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::CONFLICT, json!("item_in_case"))
    );
    assert_eq!(problem["case_number"], second["number"]);
    fx.db.drop().await;
}

#[tokio::test]
async fn items_can_be_removed_and_assignees_are_users_who_read_cases() {
    let fx = fixture!();
    let alice = fx.session("alice").await;
    let vera = fx.session("vera").await;
    let case = fx
        .open(
            &alice,
            "Remove",
            json!([{"kind": "host", "ref": WEB}, {"kind": "alarm", "ref": fx.web_alarm}]),
        )
        .await;
    let uri = case_uri(&case);
    let alarm = item_of(&case, "alarm")["item_id"].as_str().unwrap();
    let (status, _, _) = fx
        .send(
            &alice,
            "DELETE",
            &format!("{uri}/items/{alarm}"),
            None,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, problem, _) = fx
        .send(
            &alice,
            "DELETE",
            &format!("{uri}/items/{alarm}"),
            None,
            None,
        )
        .await;
    assert_eq!(
        (status, problem["code"].clone()),
        (StatusCode::NOT_FOUND, json!("item_not_found"))
    );
    let (_, after) = fx.get(&alice, &uri).await;
    assert_eq!(after["items"].as_array().unwrap().len(), 1);
    assert!(
        after["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "item_removed" && e["detail"]["item_ref"] == fx.web_alarm)
    );
    // The alarm is free for another case.
    fx.open(
        &alice,
        "Elsewhere",
        json!([{"kind": "alarm", "ref": fx.web_alarm}]),
    )
    .await;

    let (status, assignees) = fx.get(&alice, "/api/v1/cases/assignees").await;
    assert_eq!(status, StatusCode::OK);
    let names: Vec<_> = assignees["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| u["username"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alice", "bob", "dave"], "not the viewer");
    assert_eq!(assignees["items"][0]["user_id"], ALICE);
    assert_eq!(
        fx.get(&vera, "/api/v1/cases/assignees").await.0,
        StatusCode::FORBIDDEN
    );
    // A viewer cannot be assigned, nor a stranger.
    for who in [VERA, "99999999-9999-4999-8999-999999999999", "nobody"] {
        let (status, problem, _) = fx
            .send(
                &alice,
                "PUT",
                &uri,
                Some(put_body(&after, json!({"assignee_user_id": who}))),
                Some(&version(&after)),
            )
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{who}: {problem}");
        assert_eq!(
            field_errors(&problem),
            [(
                "assignee_user_id".to_owned(),
                "assignee_unavailable".to_owned()
            )]
        );
    }
    let (status, _, _) = fx
        .send(
            &alice,
            "POST",
            "/api/v1/cases",
            Some(json!({"title": "x", "assignee_user_id": VERA})),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    // Assign, then unassign by leaving it out.
    let (_, assigned, _) = fx
        .send(
            &alice,
            "PUT",
            &uri,
            Some(put_body(&after, json!({"assignee_user_id": DAVE}))),
            Some(&version(&after)),
        )
        .await;
    assert_eq!(assigned["assignee"]["username"], "dave");
    let body =
        json!({"title": assigned["title"], "severity": assigned["severity"], "status": "open"});
    let (status, unassigned, _) = fx
        .send(&alice, "PUT", &uri, Some(body), Some(&version(&assigned)))
        .await;
    assert_eq!(status, StatusCode::OK, "{unassigned}");
    assert_eq!(unassigned["assignee"], Value::Null);
    fx.db.drop().await;
}
