//! The agent install package: one shell script that installs and enrolls an
//! agent, the same on every host. Rendering is pure; the router supplies the
//! platform's name, root certificate, rule trust and the fleet token.

use std::fmt::Write as _;

/// A rule set's trust line, as the installer's `--rules` / `--alarm-rules`
/// take it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleTrust {
    /// Rule set id.
    pub set: String,
    /// Issuer key id.
    pub issuer: String,
    /// Public key, base64url (43 characters).
    pub key: String,
}

impl RuleTrust {
    fn valid(&self) -> bool {
        let id = |s: &str| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".:_-".contains(&b))
        };
        id(&self.set)
            && id(&self.issuer)
            && self.key.len() == 43
            && self
                .key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    fn arg(&self) -> String {
        format!("{},{},{}", self.set, self.issuer, self.key)
    }
}

/// What the package is built from.
#[derive(Clone, Debug)]
pub struct PackageSpec<'a> {
    /// The platform's name as agents reach it.
    pub platform: &'a str,
    /// Agent port on the platform.
    pub ingest_port: u16,
    /// Rule distribution port on the platform.
    pub distribution_port: u16,
    /// The root certificate agents trust, PEM.
    pub root_cert_pem: &'a str,
    /// Trust for the baseline rule set, when the platform serves it.
    pub rules: Option<RuleTrust>,
    /// Trust for the alarm rule set, when served (needs `rules`).
    pub alarm_rules: Option<RuleTrust>,
    /// The fleet enrollment token.
    pub token: &'a str,
}

/// Why a package cannot be built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageError {
    /// The platform name is not a host name or address.
    Platform,
    /// The root certificate is not a single valid certificate.
    RootCertificate,
    /// The token has characters a token never has.
    Token,
    /// A rule trust line is malformed.
    Rules,
}

const DEFAULT_INGEST_PORT: u16 = 18423;
const DEFAULT_DISTRIBUTION_PORT: u16 = 18424;

fn valid_platform(name: &str) -> bool {
    name.parse::<std::net::IpAddr>().is_ok()
        || (!name.is_empty()
            && name.len() <= 253
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-'))
}

fn fingerprint(pem: &str) -> Option<String> {
    let digest = platform_pki::sha256_fingerprint(pem).ok()?;
    Some(
        digest
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// The installer command line the script runs (what `openvibes-admin agent
/// command` prints), with the token read from a variable, so it is not in a
/// process list longer than the installer needs it.
fn installer_args(spec: &PackageSpec<'_>, fingerprint: &str) -> String {
    let platform = if spec.ingest_port == DEFAULT_INGEST_PORT {
        spec.platform.to_owned()
    } else {
        format!("{}:{}", spec.platform, spec.ingest_port)
    };
    let mut args =
        format!("--agent --platform {platform} --token \"$TOKEN\" --ca-sha256 {fingerprint}");
    if let Some(rules) = &spec.rules {
        let _ = write!(args, " --rules {}", rules.arg());
        if spec.distribution_port != DEFAULT_DISTRIBUTION_PORT {
            let _ = write!(args, " --distribution-port {}", spec.distribution_port);
        }
        if let Some(alarms) = &spec.alarm_rules {
            let _ = write!(args, " --alarm-rules {}", alarms.arg());
        }
    }
    args
}

/// Renders the install script.
pub fn render(spec: &PackageSpec<'_>) -> Result<String, PackageError> {
    if !valid_platform(spec.platform) {
        return Err(PackageError::Platform);
    }
    if spec.token.is_empty()
        || spec.token.len() > 128
        || !spec
            .token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(PackageError::Token);
    }
    if spec.rules.iter().chain(&spec.alarm_rules).any(|r| !r.valid())
        || (spec.alarm_rules.is_some() && spec.rules.is_none())
    {
        return Err(PackageError::Rules);
    }
    let fingerprint = fingerprint(spec.root_cert_pem).ok_or(PackageError::RootCertificate)?;
    let args = installer_args(spec, &fingerprint);
    Ok(format!(
        "#!/bin/sh\n\
         # OpenVIBES agent install package for {platform}.\n\
         # The same file installs and enrolls the agent on any number of hosts:\n\
         #   sudo sh {name}\n\
         # It holds the fleet enrollment token; keep the file private (mode 0600)\n\
         # and rotate the token in the console if it leaks.\n\
         set -eu\n\
         if [ \"$(id -u)\" -ne 0 ]; then\n\
         \x20   echo 'run as root: sudo sh '\"$0\" >&2\n\
         \x20   exit 1\n\
         fi\n\
         TOKEN='{token}'\n\
         umask 077\n\
         work=$(mktemp -d)\n\
         trap 'rm -rf \"$work\"' EXIT\n\
         curl -fsSL https://openvibes-project.github.io/install.sh -o \"$work/install.sh\"\n\
         sh \"$work/install.sh\" {args}\n",
        platform = spec.platform,
        name = FILE_NAME,
        token = spec.token,
    ))
}

/// The download's file name.
pub const FILE_NAME: &str = "openvibes-agent-install.sh";

#[cfg(test)]
mod tests {
    use super::*;

    fn root() -> String {
        let key = rcgen::KeyPair::generate().expect("key");
        let mut params = rcgen::CertificateParams::new(vec![]).expect("params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name.push(
            rcgen::DnType::CommonName,
            rcgen::DnValue::Utf8String("Test root".into()),
        );
        params.self_signed(&key).expect("cert").pem()
    }

    fn trust(set: &str) -> RuleTrust {
        RuleTrust {
            set: set.into(),
            issuer: "issuer-1".into(),
            key: "A".repeat(43),
        }
    }

    #[test]
    fn script_carries_the_fleet_token_and_installer_arguments() {
        let pem = root();
        let script = render(&PackageSpec {
            platform: "vibes.example.com",
            ingest_port: DEFAULT_INGEST_PORT,
            distribution_port: DEFAULT_DISTRIBUTION_PORT,
            root_cert_pem: &pem,
            rules: Some(trust("baseline")),
            alarm_rules: Some(trust("baseline-alarms")),
            token: "tok_en-123",
        })
        .expect("renders");
        assert!(script.starts_with("#!/bin/sh\n"));
        assert!(script.contains("TOKEN='tok_en-123'"));
        assert!(script.contains("--platform vibes.example.com --token \"$TOKEN\" --ca-sha256 "));
        assert!(script.contains(" --rules baseline,issuer-1,"));
        assert!(script.contains(" --alarm-rules baseline-alarms,issuer-1,"));
        assert!(!script.contains("--distribution-port"));
    }

    #[test]
    fn non_default_ports_are_named() {
        let pem = root();
        let script = render(&PackageSpec {
            platform: "10.0.0.5",
            ingest_port: 9000,
            distribution_port: 9001,
            root_cert_pem: &pem,
            rules: Some(trust("baseline")),
            alarm_rules: None,
            token: "abc",
        })
        .expect("renders");
        assert!(script.contains("--platform 10.0.0.5:9000 "));
        assert!(script.contains("--distribution-port 9001"));
        assert!(!script.contains("--alarm-rules"));
    }

    #[test]
    fn hostile_input_is_refused() {
        let pem = root();
        let base = PackageSpec {
            platform: "ok.example",
            ingest_port: DEFAULT_INGEST_PORT,
            distribution_port: DEFAULT_DISTRIBUTION_PORT,
            root_cert_pem: &pem,
            rules: None,
            alarm_rules: None,
            token: "abc",
        };
        let bad = |spec: PackageSpec<'_>| render(&spec).expect_err("refused");
        assert_eq!(
            bad(PackageSpec {
                platform: "x; rm -rf /",
                ..base.clone()
            }),
            PackageError::Platform
        );
        assert_eq!(
            bad(PackageSpec {
                token: "a'$(id)",
                ..base.clone()
            }),
            PackageError::Token
        );
        assert_eq!(
            bad(PackageSpec {
                root_cert_pem: "not a certificate",
                ..base.clone()
            }),
            PackageError::RootCertificate
        );
        assert_eq!(
            bad(PackageSpec {
                alarm_rules: Some(trust("baseline-alarms")),
                ..base.clone()
            }),
            PackageError::Rules
        );
        assert_eq!(
            bad(PackageSpec {
                rules: Some(RuleTrust {
                    set: "a b".into(),
                    ..trust("x")
                }),
                ..base
            }),
            PackageError::Rules
        );
    }
}
