//! The OpenVIBES units the administration TUI may act on (admin TUI spec
//! §5). An enum, so no other unit name can be expressed.

/// One allow-listed systemd unit.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Unit {
    /// `openvibes-ingest.service`.
    Ingest,
    /// `openvibes-distribution.service`.
    Distribution,
    /// `openvibes-vulns.service`.
    Vulns,
    /// `openvibes-console.service`.
    Console,
    /// `openvibes-llm.socket`: what is enabled; it starts the model server
    /// on the first request, which stops again when idle.
    Llm,
    /// `openvibes-maintenance.timer`.
    Maintenance,
    /// `openvibes-signer.service` (own rules; no network, no readiness URL).
    Signer,
}

impl Unit {
    /// Every unit, in display order.
    pub const ALL: [Unit; 7] = [
        Unit::Ingest,
        Unit::Distribution,
        Unit::Vulns,
        Unit::Console,
        Unit::Llm,
        Unit::Maintenance,
        Unit::Signer,
    ];

    /// The systemd unit name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Unit::Ingest => "openvibes-ingest.service",
            Unit::Distribution => "openvibes-distribution.service",
            Unit::Vulns => "openvibes-vulns.service",
            Unit::Console => "openvibes-console.service",
            Unit::Llm => "openvibes-llm.socket",
            Unit::Maintenance => "openvibes-maintenance.timer",
            Unit::Signer => "openvibes-signer.service",
        }
    }

    /// A short name for screens.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Unit::Ingest => "ingest",
            Unit::Distribution => "distribution",
            Unit::Vulns => "vulns",
            Unit::Console => "console",
            Unit::Llm => "llm",
            Unit::Maintenance => "maintenance",
            Unit::Signer => "signer",
        }
    }

    /// The loopback readiness endpoint at the packaged default port. None
    /// for the llm socket: a probe through it would load the model.
    #[must_use]
    pub fn ready_url(self) -> Option<&'static str> {
        match self {
            Unit::Ingest => Some("http://127.0.0.1:18480/ready"),
            Unit::Distribution => Some("http://127.0.0.1:18481/ready"),
            Unit::Vulns => Some("http://127.0.0.1:18483/ready"),
            Unit::Console => Some("http://127.0.0.1:18482/ready"),
            Unit::Llm | Unit::Maintenance | Unit::Signer => None,
        }
    }

    /// The unit with exactly this systemd name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Unit> {
        Unit::ALL.into_iter().find(|unit| unit.name() == name)
    }
}
