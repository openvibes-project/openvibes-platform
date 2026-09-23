use std::{fs::File, io::Read, path::Path, sync::Arc};

use rustls::{
    RootCertStore, ServerConfig, SupportedCipherSuite,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    server::WebPkiClientVerifier,
};

use crate::{IngestConfig, IngestError};

/// Largest certificate or key file read.
const MAX_PEM_BYTES: u64 = 1024 * 1024;

pub(crate) fn read_pem(path: &Path) -> Result<String, IngestError> {
    let mut text = String::new();
    let read = File::open(path)
        .and_then(|file| file.take(MAX_PEM_BYTES + 1).read_to_string(&mut text))
        .map_err(|_| IngestError::Tls)?;
    if read as u64 > MAX_PEM_BYTES {
        return Err(IngestError::Tls);
    }
    Ok(text)
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, IngestError> {
    let pem = read_pem(path)?;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|_| IngestError::Tls)?;
    if certs.is_empty() {
        return Err(IngestError::Tls);
    }
    Ok(certs)
}

/// TLS 1.3 only; a client certificate is optional at the handshake (for
/// enrollment) but must chain to `client_ca_file` when presented.
pub(crate) fn server_config(config: &IngestConfig) -> Result<Arc<ServerConfig>, IngestError> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)));
    let provider = Arc::new(provider);
    let mut roots = RootCertStore::empty();
    for cert in certificates(&config.client_ca_file)? {
        roots.add(cert).map_err(|_| IngestError::Tls)?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|_| IngestError::Tls)?;
    let key = PrivateKeyDer::from_pem_slice(read_pem(&config.server_key_file)?.as_bytes())
        .map_err(|_| IngestError::Tls)?;
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| IngestError::Tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(&config.server_certificate_file)?, key)
        .map_err(|_| IngestError::Tls)?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(server))
}
