//! A complete test world: database, PKI, the real ingest server in-process,
//! and a raw TLS client for requests the agent's client cannot make.
#![allow(dead_code)]

use std::{
    hash::{BuildHasher, Hasher},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use chrono::{Duration, Utc};
use openvibes_ingest::IngestConfig;
use platform_pki::{Issuer, KeyAndCert};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_rustls::TlsConnector;

pub struct World {
    pub dir: PathBuf,
    pub root: KeyAndCert,
    pub issuer: Arc<Issuer>,
    pub addr: SocketAddr,
    pub health: SocketAddr,
    pub admin_url: String,
    pub url: String,
    name: String,
    shutdown: Option<oneshot::Sender<()>>,
    server: Option<tokio::task::JoinHandle<()>>,
}

fn with_database(url: &str, name: &str) -> String {
    let (head, query) = url
        .split_once('?')
        .map_or((url, None), |(h, q)| (h, Some(q)));
    let head = &head[..head.rfind('/').unwrap()];
    query.map_or(format!("{head}/{name}"), |query| {
        format!("{head}/{name}?{query}")
    })
}

impl World {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(tune: impl FnOnce(&mut IngestConfig)) -> Self {
        let admin_url = std::env::var("OPENVIBES_TEST_DATABASE_URL")
            .expect("set OPENVIBES_TEST_DATABASE_URL, see scripts/test-db.sh");
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u64(std::process::id().into());
        let name = format!("ov_ingest_{:016x}", hasher.finish());
        let admin = platform_store::connect(&admin_url).await.unwrap();
        admin
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("CREATE DATABASE {name}"))
            .await
            .unwrap();
        let url = with_database(&admin_url, &name);
        let pool = platform_store::connect(&url).await.unwrap();
        let mut client = pool.get().await.unwrap();
        platform_store::migrate(&mut client).await.unwrap();
        let today = Utc::now().date_naive();
        platform_store::ensure_partitions(&client, today - Duration::days(90), 97)
            .await
            .unwrap();

        let dir = std::env::temp_dir().join(&name);
        std::fs::create_dir_all(&dir).unwrap();
        let now = Utc::now();
        let root = platform_pki::generate_root(now).unwrap();
        let (request, key) = platform_pki::intermediate_request().unwrap();
        let intermediate = platform_pki::sign_intermediate(&root, &request, now).unwrap();
        let issuer = Arc::new(Issuer::load(&intermediate, &key).unwrap());
        let server = issuer.issue_server(&["127.0.0.1".into()], now).unwrap();
        let write = |file: &str, text: &str| {
            std::fs::write(dir.join(file), text).unwrap();
            dir.join(file)
        };
        let mut config = IngestConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            health_listen: "127.0.0.1:0".parse().unwrap(),
            server_certificate_file: write("server.crt", &server.cert_pem),
            server_key_file: write("server.key", &server.key_pem),
            client_ca_file: write("client-ca.crt", &intermediate),
            issuing_certificate_file: write("intermediate.crt", &intermediate),
            issuing_key_file: write("intermediate.key", &key),
            database_url: url.clone(),
            client_certificate_days: 30,
            max_in_flight: 64,
            finding_retention_days: 90,
            request_timeout_seconds: 10,
        };
        tune(&mut config);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let health_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (addr, health) = (
            listener.local_addr().unwrap(),
            health_listener.local_addr().unwrap(),
        );
        let (shutdown, stop) = oneshot::channel();
        let task = tokio::spawn(async move {
            openvibes_ingest::run(config, listener, health_listener, async {
                let _ = stop.await;
            })
            .await
            .unwrap();
        });
        Self {
            dir,
            root,
            issuer,
            addr,
            health,
            admin_url,
            url,
            name,
            shutdown: Some(shutdown),
            server: Some(task),
        }
    }

    pub async fn db(&self) -> platform_store::Client {
        platform_store::connect(&self.url)
            .await
            .unwrap()
            .get()
            .await
            .unwrap()
    }

    /// Creates an enrollment token and returns it.
    pub async fn token(&self, uses: i32, expires: Duration) -> String {
        use base64::Engine;
        let bytes: [u8; 32] = std::array::from_fn(rand_byte);
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        platform_store::tokens::create(
            &self.db().await,
            &platform_store::tokens::NewToken {
                token_sha256: platform_pki::enrollment_token_sha256(&token).unwrap(),
                label: None,
                created_by: "test".into(),
                expires_at: Utc::now() + expires,
                max_uses: uses,
            },
        )
        .await
        .unwrap();
        token
    }

    /// The agent's transport configuration for this server.
    pub fn transport(&self) -> openvibes_transport::TransportConfig {
        openvibes_transport::TransportConfig {
            base_url: format!("https://{}", self.addr),
            default_port: openvibes_transport::DEFAULT_PLATFORM_PORT,
            server_roots_pem: self.root.cert_pem.clone().into_bytes(),
            proxy_url: None,
            limits: openvibes_core::ResourceLimits::V1,
        }
    }

    /// A client certificate for `agent_id` issued by this world's
    /// intermediate but **not** recorded in the database.
    pub fn unrecorded_client(&self, agent_id: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        let checked = platform_pki::check_csr(&csr).unwrap();
        let issued = self
            .issuer
            .issue_client(&checked, agent_id, Utc::now(), 30)
            .unwrap();
        (issued.chain_pem.concat(), key.serialize_pem())
    }

    /// One HTTP/1.1 request over TLS 1.3; returns the status and body, or
    /// `None` when the server refused the connection or TLS.
    pub async fn raw(
        &self,
        path: &str,
        body: &[u8],
        client: Option<(&str, &str)>,
    ) -> Option<(u16, String)> {
        raw_tls(
            self.addr,
            &self.root.cert_pem,
            path,
            body,
            client,
            &rustls::version::TLS13,
        )
        .await
    }

    pub async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(server) = self.server.take() {
            let _ = server.await;
        }
        let admin = platform_store::connect(&self.admin_url).await.unwrap();
        let _ = admin
            .get()
            .await
            .unwrap()
            .batch_execute(&format!(
                "DROP DATABASE IF EXISTS {} WITH (FORCE)",
                self.name
            ))
            .await;
        let _ = std::fs::remove_dir_all(&self.dir);
    }

    pub async fn drop_database(&self) {
        let admin = platform_store::connect(&self.admin_url).await.unwrap();
        admin
            .get()
            .await
            .unwrap()
            .batch_execute(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .await
            .unwrap();
    }
}

fn rand_byte(index: usize) -> u8 {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_usize(index);
    hasher.finish() as u8
}

pub async fn raw_tls(
    addr: SocketAddr,
    root_pem: &str,
    path: &str,
    body: &[u8],
    client: Option<(&str, &str)>,
    version: &'static rustls::SupportedProtocolVersion,
) -> Option<(u16, String)> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(root_pem.as_bytes()) {
        roots.add(cert.unwrap()).unwrap();
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[version])
        .unwrap()
        .with_root_certificates(roots);
    let config = match client {
        Some((chain, key)) => {
            let chain: Vec<CertificateDer<'static>> =
                CertificateDer::pem_slice_iter(chain.as_bytes())
                    .map(Result::unwrap)
                    .collect();
            builder
                .with_client_auth_cert(
                    chain,
                    PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
                )
                .unwrap()
        }
        None => builder.with_no_client_auth(),
    };
    let tcp = TcpStream::connect(addr).await.ok()?;
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
        .await
        .ok()?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    tls.write_all(head.as_bytes()).await.ok()?;
    tls.write_all(body).await.ok()?;
    let mut response = Vec::new();
    let _ = tls.read_to_end(&mut response).await;
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text.split_whitespace().nth(1)?.parse().ok()?;
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    Some((status, body))
}

/// Plain HTTP GET to the loopback health listener.
pub async fn health_get(addr: SocketAddr, path: &str) -> u16 {
    let mut tcp = TcpStream::connect(addr).await.unwrap();
    tcp.write_all(
        format!("GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    let mut response = String::new();
    tcp.read_to_string(&mut response).await.unwrap();
    response.split_whitespace().nth(1).unwrap().parse().unwrap()
}
