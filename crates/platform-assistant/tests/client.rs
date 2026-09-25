//! The backend client against a mock OpenAI-compatible server: streaming,
//! tool calls, standard fields only, status handling, size limits,
//! deadlines, and TLS with a pinned CA and mutual TLS (spec §6, §10).

mod support;

use std::{
    collections::BTreeSet,
    time::{Duration, Instant},
};

use platform_assistant::{
    BackendClient, BackendError, ChatRequest, FinishReason, JsonSchemaFormat, Message,
    STANDARD_FIELDS, ToolCall, ToolSpec,
};
use serde_json::json;
use support::{Mock, Reply, backend, finish, pki, scratch, serve, serve_tls, text, write};

fn ask(question: &str) -> ChatRequest {
    ChatRequest {
        messages: vec![
            Message::System("You answer briefly.".into()),
            Message::User(question.into()),
        ],
        tools: Vec::new(),
        response_format: None,
        max_tokens: 64,
        temperature: 0.0,
    }
}

fn client(mock: &Mock) -> BackendClient {
    BackendClient::new(&backend(&mock.url, "")).unwrap()
}

#[test]
fn streams_text_across_split_frames() {
    let mock = serve(Box::new(|_| {
        let chunk = |value: serde_json::Value| format!("data: {value}\n\n");
        let first = chunk(text("Two hosts"));
        // One event split mid-JSON across HTTP chunks, a comment line, a
        // multi-line data field, CRLF line ends, and an event name.
        let (left, right) = first.split_at(first.len() / 2);
        Reply::Stream {
            status: 200,
            parts: vec![
                ": keep-alive\n\n".into(),
                left.into(),
                right.into(),
                "event: message\r\ndata: {\"choices\":[{\"index\":0,\r\ndata: \"delta\":{\"content\":\" match.\"}}]}\r\n\r\n".into(),
                chunk(finish("stop")),
                chunk(json!({ "choices": [], "usage": { "prompt_tokens": 20, "completion_tokens": 4 } })),
                "data: [DONE]\n\n".into(),
            ],
        }
    }));
    let mut pieces = Vec::new();
    let response = client(&mock)
        .chat(&ask("How many?"), |piece| pieces.push(piece.to_owned()))
        .unwrap();
    assert_eq!(response.content, "Two hosts match.");
    assert_eq!(pieces, ["Two hosts", " match."]);
    assert_eq!(response.finish, FinishReason::Stop);
    assert_eq!(response.chunks, 2);
    assert_eq!(response.usage.unwrap().completion_tokens, 4);
    assert!(response.first_token.is_some());
    assert!(response.tool_calls.is_empty());
}

#[test]
fn assembles_tool_calls_from_deltas() {
    let mock = serve(Box::new(|_| {
        let call = |index: u64, value: serde_json::Value| json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [ { "index": index, "function": value } ] } }] });
        Reply::events(&[
            json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [
                { "index": 0, "id": "call_a", "type": "function", "function": { "name": "search_findings", "arguments": "" } }
            ] } }] }),
            call(0, json!({ "arguments": "{\"severity\":" })),
            call(0, json!({ "arguments": "\"high\"}" })),
            json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [
                { "index": 1, "id": "call_b", "function": { "name": "fleet_overview", "arguments": "{}" } }
            ] } }] }),
            finish("tool_calls"),
        ])
    }));
    let response = client(&mock)
        .chat(&ask("Serious findings?"), |_| {})
        .unwrap();
    assert_eq!(response.finish, FinishReason::ToolCalls);
    assert_eq!(
        response.tool_calls,
        vec![
            ToolCall {
                id: "call_a".into(),
                name: "search_findings".into(),
                arguments: "{\"severity\":\"high\"}".into()
            },
            ToolCall {
                id: "call_b".into(),
                name: "fleet_overview".into(),
                arguments: "{}".into()
            },
        ]
    );
}

#[test]
fn requests_carry_only_standard_fields() {
    let mock = serve(Box::new(|_| Reply::events(&[text("ok"), finish("stop")])));
    let dir = scratch("standard-fields");
    let key = write(&dir, "key", "sk-test\n", 0o600);
    let client =
        BackendClient::new(&backend(&mock.url, &format!("api_key_file = {key:?}"))).unwrap();
    let mut request = ask("hi");
    request.messages.push(Message::Assistant {
        content: None,
        tool_calls: vec![ToolCall {
            id: "call_1".into(),
            name: "fleet_overview".into(),
            arguments: "{}".into(),
        }],
    });
    request.messages.push(Message::Tool {
        call_id: "call_1".into(),
        content: "3 agents".into(),
    });
    request.tools = vec![ToolSpec {
        name: "fleet_overview".into(),
        description: "Fleet counts.".into(),
        parameters: json!({ "type": "object", "properties": {} }),
    }];
    request.response_format = Some(JsonSchemaFormat {
        name: "answer".into(),
        schema: json!({ "type": "object" }),
    });
    client.chat(&request, |_| {}).unwrap();

    let seen = mock.requests();
    assert_eq!(seen.len(), 1);
    assert_eq!(
        (seen[0].method.as_str(), seen[0].path.as_str()),
        ("POST", "/v1/chat/completions")
    );
    assert_eq!(seen[0].header("authorization"), Some("Bearer sk-test"));
    let body = seen[0].json();
    let fields: BTreeSet<&str> = body
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let allowed: BTreeSet<&str> = STANDARD_FIELDS.iter().copied().collect();
    assert!(
        fields.is_subset(&allowed),
        "non-standard fields: {:?}",
        fields.difference(&allowed)
    );
    assert_eq!(body["model"], "test-model");
    assert_eq!(body["stream"], true);
    assert_eq!(
        body["messages"][2]["tool_calls"][0]["function"]["name"],
        "fleet_overview"
    );
    assert_eq!(body["messages"][3]["role"], "tool");
    assert_eq!(body["messages"][3]["tool_call_id"], "call_1");
    assert_eq!(body["tools"][0]["type"], "function");
    assert_eq!(body["response_format"]["type"], "json_schema");
}

#[test]
fn no_authorization_header_without_a_key() {
    let mock = serve(Box::new(|_| Reply::events(&[text("ok"), finish("stop")])));
    client(&mock).chat(&ask("hi"), |_| {}).unwrap();
    assert_eq!(mock.requests()[0].header("authorization"), None);
}

#[test]
fn a_non_streaming_answer_is_accepted() {
    let mock = serve(Box::new(|_| {
        Reply::json(
            200,
            json!({ "choices": [{ "index": 0, "finish_reason": "stop",
                "message": { "role": "assistant", "content": "Plain answer.", "tool_calls": null } }] }),
        )
    }));
    let response = client(&mock).chat(&ask("hi"), |_| {}).unwrap();
    assert_eq!(response.content, "Plain answer.");
    assert_eq!(response.finish, FinishReason::Stop);
}

#[test]
fn statuses_map_to_fixed_errors_and_redirects_are_not_followed() {
    for (status, expected) in [
        (400, BackendError::Rejected),
        (401, BackendError::Unauthorized),
        (403, BackendError::Unauthorized),
        (404, BackendError::NotFound),
        (429, BackendError::RateLimited),
        (500, BackendError::Unavailable),
        (503, BackendError::Unavailable),
    ] {
        let mock = serve(Box::new(move |_| {
            Reply::json(
                status,
                json!({ "error": { "message": "secret backend detail" } }),
            )
        }));
        let error = client(&mock).chat(&ask("hi"), |_| {}).unwrap_err();
        assert_eq!(error, expected, "{status}");
        assert!(!error.to_string().contains("secret"));
    }
    let mock = serve(Box::new(|_| Reply::Body {
        status: 302,
        content_type: "text/plain",
        body: Vec::new(),
        extra_headers: vec![("location", "http://127.0.0.1:1/elsewhere")],
    }));
    assert_eq!(
        client(&mock).chat(&ask("hi"), |_| {}).unwrap_err(),
        BackendError::Rejected
    );
    assert_eq!(mock.requests().len(), 1, "the redirect was not followed");
}

#[test]
fn hostile_or_broken_streams_are_refused() {
    let long_line = format!("data: {}\n\n", "x".repeat(300 * 1024));
    let too_many_calls: Vec<_> = (0..9)
        .map(|index| {
            json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [
                { "index": index, "id": format!("c{index}"), "function": { "name": "fleet_overview", "arguments": "{}" } }
            ] } }] })
        })
        .collect();
    let huge_arguments = json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [
        { "index": 0, "id": "c", "function": { "name": "x", "arguments": "a".repeat(17 * 1024) } }
    ] } }] });
    let cases: Vec<(&str, Reply, BackendError)> = vec![
        (
            "a line over the limit",
            Reply::Stream {
                status: 200,
                parts: vec![long_line],
            },
            BackendError::ResponseTooLarge,
        ),
        (
            "a body over the limit",
            Reply::Stream {
                status: 200,
                parts: (0..40)
                    .map(|_| format!("data: {}\n\n", text(&"y".repeat(200 * 1024))))
                    .collect(),
            },
            BackendError::ResponseTooLarge,
        ),
        (
            "more than 8 tool calls",
            Reply::events(&too_many_calls),
            BackendError::InvalidResponse,
        ),
        (
            "oversized tool arguments",
            Reply::events(&[huge_arguments]),
            BackendError::ResponseTooLarge,
        ),
        (
            "malformed JSON",
            Reply::Stream {
                status: 200,
                parts: vec!["data: {not json\n\n".into()],
            },
            BackendError::InvalidResponse,
        ),
        (
            "an error object mid-stream",
            Reply::events(&[text("partial"), json!({ "error": { "message": "boom" } })]),
            BackendError::InvalidResponse,
        ),
        (
            "cut off before the end",
            Reply::Stream {
                status: 200,
                parts: vec![format!("data: {}\n\n", text("partial"))],
            },
            BackendError::InvalidResponse,
        ),
        (
            "a tool call without a name",
            Reply::events(&[
                json!({ "choices": [{ "index": 0, "delta": { "tool_calls": [ { "index": 0, "function": { "arguments": "{}" } } ] } }] }),
                finish("tool_calls"),
            ]),
            BackendError::InvalidResponse,
        ),
    ];
    for (name, reply, expected) in cases {
        let reply = std::sync::Mutex::new(Some(reply));
        let mock = serve(Box::new(move |_| reply.lock().unwrap().take().unwrap()));
        assert_eq!(
            client(&mock).chat(&ask("hi"), |_| {}).unwrap_err(),
            expected,
            "{name}"
        );
    }
}

#[test]
fn the_deadline_bounds_a_silent_backend() {
    let mock = serve(Box::new(|_| Reply::Stall(Duration::from_secs(6))));
    let client = BackendClient::new(&backend(&mock.url, "deadline_seconds = 2")).unwrap();
    let started = Instant::now();
    assert_eq!(
        client.chat(&ask("hi"), |_| {}).unwrap_err(),
        BackendError::Timeout
    );
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn an_unreachable_backend_is_a_connect_error() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let client = BackendClient::new(&backend(&format!("http://127.0.0.1:{port}/v1"), "")).unwrap();
    assert_eq!(
        client.chat(&ask("hi"), |_| {}).unwrap_err(),
        BackendError::Connect
    );
}

#[test]
fn models_are_listed_and_bounded() {
    let mock = serve(Box::new(|seen| {
        assert_eq!(seen.path, "/v1/models");
        let mut data: Vec<_> = (0..250)
            .map(|i| json!({ "id": format!("model-{i}") }))
            .collect();
        data.push(json!({ "id": "bad\u{7}name" }));
        Reply::json(200, json!({ "object": "list", "data": data }))
    }));
    let models = client(&mock).models().unwrap();
    assert_eq!(models.len(), 200);
    assert_eq!(models[0], "model-0");
}

#[test]
fn tls_uses_only_the_pinned_ca() {
    let pki = pki();
    let dir = scratch("tls");
    let mock = serve_tls(
        Box::new(|_| Reply::events(&[text("secure"), finish("stop")])),
        &pki.server_cert_pem,
        &pki.server_key_pem,
        None,
    );
    let ca = write(&dir, "ca.pem", &pki.root_pem, 0o644);
    let trusted = BackendClient::new(&backend(&mock.url, &format!("ca_file = {ca:?}"))).unwrap();
    assert_eq!(trusted.chat(&ask("hi"), |_| {}).unwrap().content, "secure");

    let other = write(&dir, "other.pem", &support::pki().root_pem, 0o644);
    let untrusted =
        BackendClient::new(&backend(&mock.url, &format!("ca_file = {other:?}"))).unwrap();
    assert_eq!(
        untrusted.chat(&ask("hi"), |_| {}).unwrap_err(),
        BackendError::Tls
    );
    // Without a pinned CA only public roots are trusted, which do not
    // include a private CA.
    let public = BackendClient::new(&backend(&mock.url, "")).unwrap();
    assert_eq!(
        public.chat(&ask("hi"), |_| {}).unwrap_err(),
        BackendError::Tls
    );
}

#[test]
fn mutual_tls_presents_the_client_certificate() {
    let pki = pki();
    let dir = scratch("mtls");
    let mock = serve_tls(
        Box::new(|_| Reply::events(&[text("hello client"), finish("stop")])),
        &pki.server_cert_pem,
        &pki.server_key_pem,
        Some(pki.issuer.cert_pem()),
    );
    let ca = write(&dir, "ca.pem", &pki.root_pem, 0o644);
    let (chain, key) = pki.client();
    let cert = write(&dir, "client.crt", &chain, 0o644);
    let key = write(&dir, "client.key", &key, 0o600);
    let with_identity = BackendClient::new(&backend(
        &mock.url,
        &format!("ca_file = {ca:?}\nclient_certificate_file = {cert:?}\nclient_key_file = {key:?}"),
    ))
    .unwrap();
    assert_eq!(
        with_identity.chat(&ask("hi"), |_| {}).unwrap().content,
        "hello client"
    );

    let without = BackendClient::new(&backend(&mock.url, &format!("ca_file = {ca:?}"))).unwrap();
    let error = without.chat(&ask("hi"), |_| {}).unwrap_err();
    assert!(
        matches!(error, BackendError::Tls | BackendError::Connect),
        "{error:?}"
    );
}

#[test]
fn unusable_certificate_files_fail_at_construction() {
    let dir = scratch("bad-certs");
    let ca = write(&dir, "ca.pem", "not a certificate", 0o644);
    assert_eq!(
        BackendClient::new(&backend(
            "https://127.0.0.1:8443/v1",
            &format!("ca_file = {ca:?}")
        ))
        .unwrap_err(),
        BackendError::InvalidConfig
    );
}
