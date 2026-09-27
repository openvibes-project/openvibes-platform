//! A mock OpenAI-compatible backend: records every request and answers with
//! scripted replies, over plain HTTP on loopback or TLS 1.3 (optionally
//! requiring a client certificate).
#![allow(dead_code)]

use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};

use chrono::Utc;
use platform_assistant::{AssistantConfig, Backend};
use rustls::{
    RootCertStore, ServerConfig, ServerConnection, StreamOwned, SupportedCipherSuite,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};

/// One request as the mock received it.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// A scripted reply.
pub enum Reply {
    /// `text/event-stream`, each part written as its own HTTP chunk.
    Stream { status: u16, parts: Vec<String> },
    /// A complete body with a content type.
    Body {
        status: u16,
        content_type: &'static str,
        body: Vec<u8>,
        extra_headers: Vec<(&'static str, &'static str)>,
    },
    /// Say nothing for this long, then close.
    Stall(Duration),
}

impl Reply {
    pub fn json(status: u16, body: serde_json::Value) -> Self {
        Self::Body {
            status,
            content_type: "application/json",
            body: serde_json::to_vec(&body).unwrap(),
            extra_headers: Vec::new(),
        }
    }

    /// A stream of `data:` events built from JSON chunks, ending in `[DONE]`.
    pub fn events(chunks: &[serde_json::Value]) -> Self {
        let mut parts: Vec<String> = chunks
            .iter()
            .map(|chunk| format!("data: {chunk}\n\n"))
            .collect();
        parts.push("data: [DONE]\n\n".into());
        Self::Stream { status: 200, parts }
    }
}

pub type Handler = Box<dyn Fn(&Seen) -> Reply + Send + Sync>;

pub struct Mock {
    /// Base URL, ending in `/v1`.
    pub url: String,
    pub seen: Arc<Mutex<Vec<Seen>>>,
}

impl Mock {
    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }
}

/// A text delta chunk.
pub fn text(piece: &str) -> serde_json::Value {
    serde_json::json!({ "choices": [{ "index": 0, "delta": { "content": piece } }] })
}

/// A finish chunk.
pub fn finish(reason: &str) -> serde_json::Value {
    serde_json::json!({ "choices": [{ "index": 0, "delta": {}, "finish_reason": reason }] })
}

/// Plain HTTP on 127.0.0.1.
pub fn serve(handler: Handler) -> Mock {
    start(handler, None, "http")
}

/// TLS 1.3 on 127.0.0.1 with `cert_pem`/`key_pem`; with `client_ca_pem`,
/// a client certificate chaining to it is required.
pub fn serve_tls(
    handler: Handler,
    cert_pem: &str,
    key_pem: &str,
    client_ca_pem: Option<&str>,
) -> Mock {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)));
    let provider = Arc::new(provider);
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap();
    let builder = match client_ca_pem {
        Some(ca) => {
            let mut roots = RootCertStore::empty();
            for cert in CertificateDer::pem_slice_iter(ca.as_bytes()) {
                roots.add(cert.unwrap()).unwrap();
            }
            builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                    .build()
                    .unwrap(),
            )
        }
        None => builder.with_no_client_auth(),
    };
    let certs: Vec<_> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .map(Result::unwrap)
        .collect();
    let key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    let config = Arc::new(builder.with_single_cert(certs, key).unwrap());
    start(handler, Some(config), "https")
}

fn start(handler: Handler, tls: Option<Arc<ServerConfig>>, scheme: &str) -> Mock {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("{scheme}://{}/v1", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let handler = Arc::new(handler);
    let log = seen.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { continue };
            let (handler, log, tls) = (handler.clone(), log.clone(), tls.clone());
            thread::spawn(move || match tls {
                Some(config) => {
                    let Ok(connection) = ServerConnection::new(config) else {
                        return;
                    };
                    let _ = handle(StreamOwned::new(connection, stream), &handler, &log);
                }
                None => {
                    let _ = handle(stream, &handler, &log);
                }
            });
        }
    });
    Mock { url, seen }
}

fn handle(
    stream: impl Read + Write,
    handler: &Handler,
    log: &Mutex<Vec<Seen>>,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let path = parts.next().unwrap_or("").to_owned();
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line)?;
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
        }
    }
    let length = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, value)| value.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0; length];
    reader.read_exact(&mut body)?;
    let seen = Seen {
        method,
        path,
        headers,
        body,
    };
    log.lock().unwrap().push(seen.clone());
    let reply = handler(&seen);
    let stream = reader.get_mut();
    match reply {
        Reply::Stall(duration) => {
            thread::sleep(duration);
        }
        Reply::Body {
            status,
            content_type,
            body,
            extra_headers,
        } => {
            let mut head = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n",
                body.len()
            );
            for (name, value) in extra_headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            stream.write_all(head.as_bytes())?;
            stream.write_all(&body)?;
        }
        Reply::Stream { status, parts } => {
            stream.write_all(
                format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n"
                )
                .as_bytes(),
            )?;
            for part in parts {
                stream.write_all(format!("{:x}\r\n{part}\r\n", part.len()).as_bytes())?;
                stream.flush()?;
            }
            stream.write_all(b"0\r\n\r\n")?;
        }
    }
    stream.flush()
}

/// A fresh directory for one test's files.
pub fn scratch(test: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("ov-assistant-{}", std::process::id()))
        .join(test);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Writes `text` to `dir/name` with `mode` (Unix) and returns the path.
pub fn write(dir: &Path, name: &str, text: &str, mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    let _ = mode;
    path
}

/// Parses an `[assistant]` TOML section and validates it.
pub fn assistant(
    toml: &str,
) -> Result<platform_assistant::Assistant, platform_assistant::ConfigError> {
    toml::from_str::<AssistantConfig>(toml).unwrap().validate()
}

/// A validated local backend for `url` with `extra` backend settings.
pub fn backend(url: &str, extra: &str) -> Backend {
    assistant(&format!(
        "enabled = true\n[backend]\nurl = \"{url}\"\nmodel = \"test-model\"\n{extra}"
    ))
    .unwrap()
    .backend
    .unwrap()
}

/// A test PKI: a root, an intermediate issuer, and a server certificate
/// for 127.0.0.1.
pub struct Pki {
    pub root_pem: String,
    pub issuer: platform_pki::Issuer,
    pub server_cert_pem: String,
    pub server_key_pem: String,
}

pub fn pki() -> Pki {
    let now = Utc::now();
    let root = platform_pki::generate_root(now).unwrap();
    let (request, key) = platform_pki::intermediate_request().unwrap();
    let intermediate = platform_pki::sign_intermediate(&root, &request, now).unwrap();
    let issuer = platform_pki::Issuer::load(&intermediate, &key).unwrap();
    let server = issuer.issue_server(&["127.0.0.1".into()], now).unwrap();
    Pki {
        root_pem: root.cert_pem,
        issuer,
        server_cert_pem: server.cert_pem,
        server_key_pem: server.key_pem,
    }
}

impl Pki {
    /// A client certificate chain and key issued by the intermediate.
    pub fn client(&self) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        let checked = platform_pki::check_csr(&csr).unwrap();
        let issued = self
            .issuer
            .issue_client(
                &checked,
                "agent.00000000-0000-4000-8000-000000000001",
                Utc::now(),
                30,
            )
            .unwrap();
        (issued.chain_pem.concat(), key.serialize_pem())
    }
}
