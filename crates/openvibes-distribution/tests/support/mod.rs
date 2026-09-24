//! A test world: database, PKI, the real distribution server in-process,
//! agents recorded directly in the database, and raw TLS clients.
#![allow(dead_code)]

use std::{
    hash::{BuildHasher, Hasher},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use chrono::{Duration, Utc};
use openvibes_core::{Identifier, ResourceLimits, RuleBundleRequest, SchemaVersion};
use openvibes_distribution::DistributionConfig;
use openvibes_transport::{ClientIdentity, PlatformClient, TransportConfig, TransportError};
use platform_pki::{Issuer, KeyAndCert};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

/// A client certificate chain and key, both PEM.
pub struct Agent {
    pub id: String,
    pub chain: Vec<String>,
    pub key: String,
}

impl Agent {
    pub fn pem(&self) -> (String, &str) {
        (self.chain.concat(), &self.key)
    }
}

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

fn unique(prefix: &str) -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u64(std::process::id().into());
    format!("{prefix}_{:016x}", hasher.finish())
}

impl World {
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    pub async fn start_with(tune: impl FnOnce(&mut DistributionConfig)) -> Self {
        let admin_url = std::env::var("OPENVIBES_TEST_DATABASE_URL")
            .expect("set OPENVIBES_TEST_DATABASE_URL, see scripts/test-db.sh");
        let name = unique("ov_dist");
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
        platform_store::migrate(&mut pool.get().await.unwrap())
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
        let mut config = DistributionConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            health_listen: "127.0.0.1:0".parse().unwrap(),
            server_certificate_file: write("server.crt", &server.cert_pem),
            server_key_file: write("server.key", &server.key_pem),
            client_ca_file: write("client-ca.crt", &intermediate),
            database_url: url.clone(),
            max_in_flight: 64,
            request_timeout_seconds: 10,
            max_connections: 256,
            database_pool_size: 16,
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
            openvibes_distribution::run(config, listener, health_listener, async {
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

    /// A certificate issued by this world's intermediate, valid from
    /// `not_before` for `days`.
    pub fn certificate(
        &self,
        agent_id: &str,
        not_before: chrono::DateTime<Utc>,
        days: u32,
    ) -> (platform_pki::IssuedClient, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let csr = params.serialize_request(&key).unwrap().pem().unwrap();
        let checked = platform_pki::check_csr(&csr).unwrap();
        let issued = self
            .issuer
            .issue_client(&checked, agent_id, not_before, days)
            .unwrap();
        (issued, key.serialize_pem())
    }

    /// An agent recorded as active with a certificate valid from
    /// `not_before` for `days`.
    pub async fn agent_valid(&self, n: u32, not_before: chrono::DateTime<Utc>, days: u32) -> Agent {
        let id = format!("agent.00000000-0000-4000-8000-{n:012}");
        let (issued, key) = self.certificate(&id, not_before, days);
        let db = self.db().await;
        db.execute(
            "INSERT INTO agents (agent_id, status, enrolled_at) VALUES ($1, 'active', now())",
            &[&id],
        )
        .await
        .unwrap();
        platform_store::ingest::add_certificate(
            &db,
            &id,
            &platform_store::ingest::IssuedCert {
                serial: issued.serial,
                spki_sha256: issued.spki_sha256,
                not_before: issued.not_before,
                not_after: issued.not_after,
                chain_pem: issued.chain_pem.clone(),
            },
            Utc::now(),
        )
        .await
        .unwrap();
        Agent {
            id,
            chain: issued.chain_pem,
            key,
        }
    }

    /// An active agent with a current certificate.
    pub async fn agent(&self, n: u32) -> Agent {
        self.agent_valid(n, Utc::now() - Duration::minutes(5), 30)
            .await
    }

    pub async fn revoke(&self, agent: &Agent) {
        self.db()
            .await
            .execute(
                "UPDATE agents SET status = 'revoked', revoked_at = now() WHERE agent_id = $1",
                &[&agent.id],
            )
            .await
            .unwrap();
    }

    /// Trusts a key for `set` (once) and stores `envelope` as `version`;
    /// the store does not verify signatures, `openvibes-admin` does.
    pub async fn publish(&self, set: &str, version: i64, envelope: &[u8]) {
        let mut db = self.db().await;
        platform_store::rules::add_trust_key(&db, set, "org.rules", [9; 32])
            .await
            .unwrap();
        let published = platform_store::rules::publish(
            &mut db,
            &platform_store::rules::NewBundle {
                rule_set_id: set,
                version,
                envelope,
                envelope_sha256: [0; 32],
                issuer_key_id: "org.rules",
                created_at_ms: 0,
                expires_at_ms: i64::MAX,
                published_by: "test",
            },
        )
        .await
        .unwrap();
        assert_eq!(published, platform_store::rules::Published::Stored);
    }

    /// The agent's own transport, as it polls before a scan.
    pub async fn fetch(
        &self,
        agent: &Agent,
        set: &str,
        current: Option<u64>,
    ) -> Result<Option<Vec<u8>>, TransportError> {
        let config = TransportConfig {
            base_url: format!("https://{}", self.addr),
            default_port: openvibes_transport::DEFAULT_DISTRIBUTION_PORT,
            server_roots_pem: self.root.cert_pem.clone().into_bytes(),
            proxy_url: None,
            limits: ResourceLimits::V1,
        };
        let identity = ClientIdentity::from_pem(&agent.chain, &agent.key).unwrap();
        let request = RuleBundleRequest {
            schema_version: SchemaVersion::V1,
            rule_set_id: Identifier::new(set).unwrap(),
            current_version: current,
        };
        tokio::task::spawn_blocking(move || {
            PlatformClient::new(&config, Some(&identity))?.fetch_rule_bundle(&request)
        })
        .await
        .unwrap()
    }

    /// One `POST /v1/rule-bundle`; returns the status, the response head,
    /// and the body, or `None` when the connection or TLS was refused.
    pub async fn raw(&self, body: &[u8], agent: Option<&Agent>) -> Option<(u16, String, Vec<u8>)> {
        let pem = agent.map(Agent::pem);
        let mut tls = self
            .connect(pem.as_ref().map(|(chain, key)| (chain.as_str(), *key)))
            .await?;
        let head = format!(
            "POST /v1/rule-bundle HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n\
             Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        tls.write_all(head.as_bytes()).await.ok()?;
        tls.write_all(body).await.ok()?;
        let mut response = Vec::new();
        let _ = tls.read_to_end(&mut response).await;
        let split = response.windows(4).position(|w| w == b"\r\n\r\n")?;
        let head = String::from_utf8_lossy(&response[..split]).into_owned();
        let status = head.split_whitespace().nth(1)?.parse().ok()?;
        Some((status, head, response[split + 4..].to_vec()))
    }

    /// A TLS 1.3 connection, with an optional client certificate.
    pub async fn connect(&self, client: Option<(&str, &str)>) -> Option<TlsStream<TcpStream>> {
        let mut roots = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(self.root.cert_pem.as_bytes()) {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots);
        let config = match client {
            Some((chain, key)) => builder
                .with_client_auth_cert(
                    CertificateDer::pem_slice_iter(chain.as_bytes())
                        .map(Result::unwrap)
                        .collect(),
                    PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        let tcp = TcpStream::connect(self.addr).await.ok()?;
        TlsConnector::from(Arc::new(config))
            .connect(ServerName::try_from("127.0.0.1").unwrap(), tcp)
            .await
            .ok()
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

pub fn request(set: &str, current: Option<u64>) -> Vec<u8> {
    let mut body = serde_json::json!({ "schema_version": 1, "rule_set_id": set });
    if let Some(current) = current {
        body["current_version"] = current.into();
    }
    body.to_string().into_bytes()
}
