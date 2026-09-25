use std::{fs::File, io::Read, path::Path, sync::Arc};

use rustls::{
    CertificateError, DigitallySignedStruct, DistinguishedName, RootCertStore, ServerConfig,
    SignatureScheme, SupportedCipherSuite,
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, PrivateKeyDer, UnixTime, pem::PemObject},
    server::{
        WebPkiClientVerifier,
        danger::{ClientCertVerified, ClientCertVerifier},
    },
};

use crate::ServerError;

/// Largest certificate or key file read.
const MAX_PEM_BYTES: u64 = 1024 * 1024;

/// Reads a PEM file of at most 1 MiB.
pub fn read_pem(path: &Path) -> Result<String, ServerError> {
    let mut text = String::new();
    let read = File::open(path)
        .and_then(|file| file.take(MAX_PEM_BYTES + 1).read_to_string(&mut text))
        .map_err(|_| ServerError::Tls)?;
    if read as u64 > MAX_PEM_BYTES {
        return Err(ServerError::Tls);
    }
    Ok(text)
}

fn certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>, ServerError> {
    let pem = read_pem(path)?;
    let certs: Vec<_> = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|_| ServerError::Tls)?;
    if certs.is_empty() {
        return Err(ServerError::Tls);
    }
    Ok(certs)
}

/// TLS 1.3 only; a client certificate is optional at the handshake (for
/// enrollment) but must chain to `client_ca_file` when presented.
pub(crate) fn server_config(
    certificate: &Path,
    key: &Path,
    client_ca: &Path,
) -> Result<Arc<ServerConfig>, ServerError> {
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, SupportedCipherSuite::Tls13(_)));
    let provider = Arc::new(provider);
    let mut roots = RootCertStore::empty();
    for cert in certificates(client_ca)? {
        roots.add(cert).map_err(|_| ServerError::Tls)?;
    }
    let inner = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .allow_unauthenticated()
        .build()
        .map_err(|_| ServerError::Tls)?;
    let verifier = Arc::new(ExpiryTolerant { inner });
    let key =
        PrivateKeyDer::from_pem_slice(read_pem(key)?.as_bytes()).map_err(|_| ServerError::Tls)?;
    let mut server = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ServerError::Tls)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certificates(certificate)?, key)
        .map_err(|_| ServerError::Tls)?;
    server.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(server))
}

/// Accepts a client certificate outside its validity period if the chain
/// otherwise verifies to the client CA, so the platform can answer at the
/// HTTP level as the protocol requires (401 when expired, 403
/// `identity_revoked` when the agent is revoked). Every other failure still
/// fails the handshake. Authentication rejects expired certificates.
#[derive(Debug)]
struct ExpiryTolerant {
    inner: Arc<dyn ClientCertVerifier>,
}

impl ClientCertVerifier for ExpiryTolerant {
    fn offer_client_auth(&self) -> bool {
        self.inner.offer_client_auth()
    }

    fn client_auth_mandatory(&self) -> bool {
        self.inner.client_auth_mandatory()
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        self.inner.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        match self
            .inner
            .verify_client_cert(end_entity, intermediates, now)
        {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::Expired
                | CertificateError::ExpiredContext { .. }
                | CertificateError::NotValidYet
                | CertificateError::NotValidYetContext { .. },
            )) => {
                // Re-verify the chain at a moment inside the leaf's validity.
                let Ok((not_before, _)) = platform_pki::leaf_validity(end_entity) else {
                    return Err(rustls::Error::InvalidCertificate(
                        CertificateError::BadEncoding,
                    ));
                };
                let at = UnixTime::since_unix_epoch(std::time::Duration::from_secs(
                    u64::try_from(not_before.timestamp())
                        .unwrap_or(0)
                        .saturating_add(1),
                ));
                self.inner.verify_client_cert(end_entity, intermediates, at)
            }
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}
