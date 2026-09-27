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
    /// `openvibes-llm.service`.
    Llm,
    /// `openvibes-maintenance.timer`.
    Maintenance,
}

impl Unit {
    /// Every unit, in display order.
    pub const ALL: [Unit; 5] = [
        Unit::Ingest,
        Unit::Distribution,
        Unit::Vulns,
        Unit::Llm,
        Unit::Maintenance,
    ];

    /// The systemd unit name.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Unit::Ingest => "openvibes-ingest.service",
            Unit::Distribution => "openvibes-distribution.service",
            Unit::Vulns => "openvibes-vulns.service",
            Unit::Llm => "openvibes-llm.service",
            Unit::Maintenance => "openvibes-maintenance.timer",
        }
    }

    /// A short name for screens.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Unit::Ingest => "ingest",
            Unit::Distribution => "distribution",
            Unit::Vulns => "vulns",
            Unit::Llm => "llm",
            Unit::Maintenance => "maintenance",
        }
    }

    /// The loopback readiness endpoint at the packaged default port.
    #[must_use]
    pub fn ready_url(self) -> Option<&'static str> {
        match self {
            Unit::Ingest => Some("http://127.0.0.1:18480/ready"),
            Unit::Distribution => Some("http://127.0.0.1:18481/ready"),
            Unit::Vulns => Some("http://127.0.0.1:18483/ready"),
            Unit::Llm => Some("http://127.0.0.1:18430/health"),
            Unit::Maintenance => None,
        }
    }

    /// The unit with exactly this systemd name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Unit> {
        Unit::ALL.into_iter().find(|unit| unit.name() == name)
    }
}
