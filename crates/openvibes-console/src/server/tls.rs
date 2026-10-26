//! Direct TLS: loading the certificate and key, the handshake, plain http on
//! the TLS port answered with a redirect, and the names the certificate
//! covers.

use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use tokio_rustls::{TlsAcceptor, server::TlsStream};

use super::listeners::CappedStream;
use crate::{ConsoleConfig, ConsoleError};

const MAX_TLS_FILE_BYTES: u64 = 1024 * 1024;

pub(super) fn read_tls_pem(path: &Path) -> Result<Vec<u8>, ConsoleError> {
    if !path.is_absolute() {
        return Err(ConsoleError::Config);
    }
    let mut bytes = Vec::new();
    let read = File::open(path)?
        .take(MAX_TLS_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if read as u64 > MAX_TLS_FILE_BYTES {
        return Err(ConsoleError::Config);
    }
    Ok(bytes)
}

pub(super) fn load_tls_acceptor(
    certificate_path: &Path,
    key_path: &Path,
) -> Result<TlsAcceptor, ConsoleError> {
    let certificate_pem = read_tls_pem(certificate_path)?;
    let certificates: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(&certificate_pem)
            .collect::<Result<_, _>>()
            .map_err(|_| ConsoleError::Config)?;
    if certificates.is_empty() {
        return Err(ConsoleError::Config);
    }
    let key_pem = read_tls_pem(key_path)?;
    let key = PrivateKeyDer::from_pem_slice(&key_pem).map_err(|_| ConsoleError::Config)?;
    let mut provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .retain(|suite| matches!(suite, rustls::SupportedCipherSuite::Tls13(_)));
    let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|_| ConsoleError::Config)?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|_| ConsoleError::Config)?;
    let mut config = config;
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(std::sync::Arc::new(config)))
}

/// Where plain http on the TLS port is sent (board #71): the served hosts
/// (`name:port`, lowercase) and the canonical origin for any other `Host`.
#[derive(Default)]
pub(super) struct PlainHttp {
    hosts: Vec<String>,
    origin: String,
}

/// A TLS handshake, or for plain http on this port a redirect to https
/// instead of TLS alert bytes a browser shows as garbage (board #71).
pub(super) async fn handshake(
    tls: TlsAcceptor,
    mut stream: CappedStream,
    plain_http: &PlainHttp,
) -> io::Result<TlsStream<CappedStream>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut first = [0_u8; 1];
    // 0x16 starts every TLS handshake record.
    if stream.stream.peek(&mut first).await? == 1 && first[0] != 0x16 {
        // Read the request head first: closing with it unread would reset
        // the connection before the browser sees the answer.
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while request.len() < 8192 && !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let read = stream.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
        }
        stream
            .write_all(&plain_http_answer(&request, plain_http))
            .await?;
        stream.shutdown().await?;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "plain HTTP on the TLS port",
        ));
    }
    tls.accept(stream).await
}

/// `301` to `https://` + the request's `Host` when this console serves it,
/// else to the canonical origin, never to a name it does not serve; a
/// plain `400` note when there is neither.
fn plain_http_answer(request: &[u8], to: &PlainHttp) -> Vec<u8> {
    let served = String::from_utf8_lossy(request)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("host")
                .then(|| value.trim().to_ascii_lowercase())
        })
        .filter(|host| crate::http::middleware::host_served(&to.hosts, host))
        .map(|host| format!("https://{host}"));
    match served.or_else(|| (!to.origin.is_empty()).then(|| to.origin.clone())) {
        Some(origin) => format!(
            "HTTP/1.1 301 Moved Permanently\r\nLocation: {origin}/\r\n\
             Content-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n\
             This OpenVIBES console speaks https only: open {origin}/\n"
        ),
        None => "HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\n\
                 Connection: close\r\n\r\nThis OpenVIBES console speaks https only.\n"
            .to_owned(),
    }
    .into_bytes()
}

/// `name:port` for every name the console's certificate covers (board #71):
/// the DNS names and IP addresses of its subjectAltName, lowercase, IPv6 in
/// brackets, and the bare name too at any port (browsers leave 443 out, and
/// a reverse proxy keeps the browser's Host). The console serves these
/// besides `public_origin`, so it opens by IP (over a VPN), as localhost
/// (through a tunnel) or through a proxy.
pub(crate) fn certificate_hosts(pem: &[u8], port: u16) -> Vec<String> {
    use x509_parser::extensions::GeneralName;
    let Some(Ok(der)) = CertificateDer::pem_slice_iter(pem).next() else {
        return Vec::new();
    };
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(&der) else {
        return Vec::new();
    };
    let Ok(Some(names)) = certificate.subject_alternative_name() else {
        return Vec::new();
    };
    let mut hosts = Vec::new();
    for name in &names.value.general_names {
        let host = match name {
            GeneralName::DNSName(dns) => dns.to_ascii_lowercase(),
            GeneralName::IPAddress(bytes) => match <[u8; 4]>::try_from(*bytes) {
                Ok(v4) => std::net::Ipv4Addr::from(v4).to_string(),
                Err(_) => match <[u8; 16]>::try_from(*bytes) {
                    Ok(v6) => format!("[{}]", std::net::Ipv6Addr::from(v6)),
                    Err(_) => continue,
                },
            },
            _ => continue,
        };
        hosts.push(format!("{host}:{port}"));
        hosts.push(host);
    }
    hosts
}

/// The served hosts, as the router has them: `public_origin`'s authority
/// and the certificate's names.
pub(super) fn plain_http(config: &ConsoleConfig, mut hosts: Vec<String>) -> PlainHttp {
    let origin = config.public_origin.clone().unwrap_or_default();
    if let Some(authority) = origin
        .parse::<axum::http::Uri>()
        .ok()
        .and_then(|uri| uri.authority().map(|a| a.as_str().to_owned()))
    {
        hosts.push(authority);
    }
    for host in &mut hosts {
        host.make_ascii_lowercase();
    }
    PlainHttp { hosts, origin }
}

#[cfg(test)]
mod certificate_hosts_tests {
    use super::certificate_hosts;

    fn pem(names: &[&str]) -> String {
        let names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        rcgen::generate_simple_self_signed(names)
            .unwrap()
            .cert
            .pem()
    }

    #[test]
    fn dns_names_and_ips_become_hosts_at_the_port() {
        let hosts = certificate_hosts(
            pem(&[
                "metabox-lnx",
                "localhost",
                "127.0.0.1",
                "192.168.1.10",
                "::1",
            ])
            .as_bytes(),
            8443,
        );
        for want in [
            "metabox-lnx:8443",
            "localhost:8443",
            "127.0.0.1:8443",
            "192.168.1.10:8443",
            "[::1]:8443",
        ] {
            assert!(
                hosts.iter().any(|h| h == want),
                "{want} missing in {hosts:?}"
            );
        }
        // A reverse proxy keeps the browser's Host, without the port.
        for want in ["metabox-lnx", "192.168.1.10", "[::1]"] {
            assert!(
                hosts.iter().any(|h| h == want),
                "{want} missing in {hosts:?}"
            );
        }
    }

    #[test]
    fn behind_a_proxy_the_bare_name_is_served_at_any_port() {
        use crate::http::middleware::host_served;
        let hosts = certificate_hosts(pem(&["console.lan"]).as_bytes(), 8443);
        assert!(host_served(&hosts, "console.lan"));
        assert!(host_served(&hosts, "console.lan:8443"));
        assert!(!host_served(&hosts, "other.lan"));
        assert!(!host_served(&hosts, "console.lan:9443"));
    }

    #[test]
    fn uppercase_names_are_served_lowercase() {
        let hosts = certificate_hosts(pem(&["MetaBox-LNX"]).as_bytes(), 8443);
        assert_eq!(hosts, ["metabox-lnx:8443", "metabox-lnx"]);
    }

    #[test]
    fn only_a_star_dot_prefix_is_a_wildcard() {
        use crate::http::middleware::host_served;
        assert!(host_served(&["*.x.y".into()], "a.x.y"));
        assert!(!host_served(&["*foo.x.y".into()], "afoo.x.y"));
        assert!(!host_served(&["*foo.x.y".into()], "a.foo.x.y"));
        assert!(!host_served(&["*".into()], "localhost"));
        assert!(!host_served(&["*:8443".into()], "localhost:8443"));
    }

    #[test]
    fn on_443_the_bare_name_is_served_too() {
        let hosts = certificate_hosts(pem(&["metabox-lnx"]).as_bytes(), 443);
        assert_eq!(hosts, ["metabox-lnx:443", "metabox-lnx"]);
    }

    fn served() -> super::PlainHttp {
        super::PlainHttp {
            hosts: vec!["metabox-lnx:8443".into(), "127.0.0.1:8443".into()],
            origin: "https://metabox-lnx:8443".into(),
        }
    }

    fn answer(request: &[u8], to: &super::PlainHttp) -> String {
        String::from_utf8(super::plain_http_answer(request, to)).unwrap()
    }

    #[test]
    fn plain_http_is_sent_to_https_on_the_same_served_host() {
        let answer = answer(
            b"GET /x HTTP/1.1\r\nhost: 127.0.0.1:8443\r\n\r\n",
            &served(),
        );
        assert!(answer.starts_with("HTTP/1.1 301 "), "{answer}");
        assert!(
            answer.contains("\r\nLocation: https://127.0.0.1:8443/\r\n"),
            "{answer}"
        );
        assert!(
            answer.ends_with("open https://127.0.0.1:8443/\n"),
            "{answer}"
        );
    }

    #[test]
    fn any_other_host_is_sent_to_the_canonical_origin() {
        // Reviewer on #99: never redirect to a name this console does not serve.
        for request in [
            &b"GET / HTTP/1.1\r\nHost: evil.example\r\n\r\n"[..],
            b"GET / HTTP/1.1\r\nHost: evil.example/\"><x\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
        ] {
            let answer = answer(request, &served());
            assert!(
                answer.contains("\r\nLocation: https://metabox-lnx:8443/\r\n"),
                "{answer}"
            );
            assert!(!answer.contains("evil"), "{answer}");
        }
        let answer = answer(b"GET / HTTP/1.1\r\n\r\n", &super::PlainHttp::default());
        assert!(
            answer.starts_with("HTTP/1.1 400 ") && !answer.contains("Location"),
            "{answer}"
        );
    }

    #[tokio::test]
    async fn a_plain_http_client_reads_the_answer() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = tokio::spawn(async move {
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:8443\r\n\r\n")
                .await
                .unwrap();
            let mut answer = String::new();
            client.read_to_string(&mut answer).await.unwrap();
            answer
        });
        let (stream, _) = listener.accept().await.unwrap();
        let permit = std::sync::Arc::new(tokio::sync::Semaphore::new(1))
            .try_acquire_owned()
            .unwrap();
        let (certificate, key) = {
            let key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            (key.cert.der().clone(), key.signing_key.serialize_der())
        };
        let config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![certificate],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key).into(),
        )
        .unwrap();
        let result = super::handshake(
            tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(config)),
            super::CappedStream {
                stream,
                _permit: permit,
            },
            &served(),
        )
        .await;
        assert!(result.is_err());
        assert!(
            client
                .await
                .unwrap()
                .contains("Location: https://127.0.0.1:8443/")
        );
    }

    #[test]
    fn a_wildcard_name_is_served_one_label_deep() {
        let hosts = certificate_hosts(pem(&["*.limebox.se"]).as_bytes(), 443);
        assert_eq!(hosts, ["*.limebox.se:443", "*.limebox.se"]);
        let to = super::PlainHttp {
            hosts,
            origin: "https://console.limebox.se".into(),
        };
        for (host, location) in [
            ("a.limebox.se", "https://a.limebox.se/"),
            ("limebox.se", "https://console.limebox.se/"),
            ("a.b.limebox.se", "https://console.limebox.se/"),
            ("evil/limebox.se", "https://console.limebox.se/"),
            ("u@evil.limebox.se", "https://console.limebox.se/"),
            ("ev\ril.limebox.se", "https://console.limebox.se/"),
        ] {
            let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            let answer = answer(request.as_bytes(), &to);
            assert!(
                answer.contains(&format!("Location: {location}\r\n")),
                "{answer}"
            );
        }
    }

    #[test]
    fn a_broken_certificate_serves_no_extra_names() {
        assert!(certificate_hosts(b"not a certificate", 8443).is_empty());
    }
}
