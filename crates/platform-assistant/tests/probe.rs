//! The capability probe picks the best lookup mode a backend supports and
//! measures its speed (spec §5, §9).

mod support;

use platform_assistant::{BackendClient, BackendError, LookupMode, ResolvedMode, probe};
use serde_json::json;
use support::{Reply, Seen, backend, finish, serve, text};

/// A backend whose tool calls and JSON-schema output work or not.
fn backend_that(native: bool, json_schema: bool) -> support::Mock {
    serve(Box::new(move |seen: &Seen| {
        if seen.path == "/v1/models" {
            return Reply::json(200, json!({ "data": [ { "id": "test-model" } ] }));
        }
        let body = seen.json();
        if body.get("tools").is_some() {
            return if native {
                Reply::events(&[
                    json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [ { "index": 0, "id": "c1",
                        "function": { "name": "lookup_probe", "arguments": "{\"word\":\"beta\"}" } } ] } }] }),
                    finish("tool_calls"),
                ])
            } else {
                Reply::json(
                    400,
                    json!({ "error": { "message": "tools not supported" } }),
                )
            };
        }
        if body.get("response_format").is_some() {
            return if json_schema {
                Reply::events(&[text("{\"word\":"), text("\"beta\"}"), finish("stop")])
            } else {
                // Ignores the format and chats instead.
                Reply::events(&[text("Beta!"), finish("stop")])
            };
        }
        let pieces: Vec<_> = (1..=30).map(|n| text(&format!("{n} "))).collect();
        let mut chunks = pieces;
        chunks.push(finish("stop"));
        chunks.push(
            json!({ "choices": [], "usage": { "prompt_tokens": 12, "completion_tokens": 30 } }),
        );
        Reply::events(&chunks)
    }))
}

fn client(mock: &support::Mock) -> BackendClient {
    BackendClient::new(&backend(&mock.url, "")).unwrap()
}

#[test]
fn auto_prefers_native_then_json_schema_then_prompted() {
    for (native, json_schema, expected) in [
        (true, true, ResolvedMode::Native),
        (false, true, ResolvedMode::JsonSchema),
        (false, false, ResolvedMode::Prompted),
    ] {
        let mock = backend_that(native, json_schema);
        let report = probe(&client(&mock), LookupMode::Auto);
        assert_eq!(report.native, Ok(native));
        assert_eq!(report.json_schema, Ok(json_schema));
        assert_eq!(report.selected, expected);
        assert!(!report.configured_mode_failed);
    }
}

#[test]
fn reports_models_and_speed() {
    let mock = backend_that(true, true);
    let report = probe(&client(&mock), LookupMode::Auto);
    assert_eq!(report.models, Ok(vec!["test-model".to_owned()]));
    assert_eq!(report.model_listed, Some(true));
    assert!(report.first_token.is_some());
    assert!(report.chunks_per_second.is_some_and(|rate| rate > 0.0));
    assert!(report.tokens_per_second.is_some_and(|rate| rate > 0.0));
}

#[test]
fn an_explicit_mode_is_kept_and_flagged_when_its_probe_fails() {
    let mock = backend_that(false, true);
    let report = probe(&client(&mock), LookupMode::Native);
    assert_eq!(report.selected, ResolvedMode::Native);
    assert!(report.configured_mode_failed);
    let report = probe(&client(&mock), LookupMode::JsonSchema);
    assert_eq!(report.selected, ResolvedMode::JsonSchema);
    assert!(!report.configured_mode_failed);
}

#[test]
fn an_unreachable_backend_is_reported_not_guessed() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = BackendClient::new(&backend(&format!("http://127.0.0.1:{port}/v1"), "")).unwrap();
    let report = probe(&client, LookupMode::Auto);
    assert_eq!(report.models, Err(BackendError::Connect));
    assert_eq!(report.model_listed, None);
    assert_eq!(report.native, Err(BackendError::Connect));
    assert_eq!(report.first_token, None);
    assert_eq!(report.selected, ResolvedMode::Prompted);
}
