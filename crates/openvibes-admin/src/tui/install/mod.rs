//! The Install screens (sub-project 3; install.py, full_advanced.py): the
//! choices in `Install`, the plan they write, and the work that runs it.
//! Installing and Finished are in `run.rs` and `finished.rs`; the install
//! runs on the worker like every other long job.

// Reached from Review, which Task 4 adds: until then only the tests start it.
#![allow(dead_code)]

pub(crate) mod finished;
mod run;
pub(super) use run::draw;
#[cfg(test)]
mod run_tests;

use platform_host::Step;

use super::run::{Call, Kind, Work};
use crate::setup::{plan::Component, ports, request::RequestState};

/// Who signs the platform's CA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ca {
    /// Your own CA signs the intermediate (`--ca careful`).
    Own,
    /// OpenVIBES makes its own root (`--ca quick`).
    OpenVibes,
}

/// The two certificates "Your own CA" adds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Which {
    Signed,
    Root,
}

/// Where the operator is in the install.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    Welcome,
    Quick,
    /// Step 1 to 5 as 0..=4; 4 is Review.
    Step(u8),
    Request,
    Add(Which),
    Running,
    Finished,
}

/// What the operator chose; the core is always installed.
pub struct Install {
    pub agent: bool,
    pub assistant: bool,
    pub hostname: String,
    /// Other names, comma separated.
    pub sans: String,
    pub ca: Ca,
    pub root_key_out: String,
    pub console_port: String,
    pub ingest_port: String,
    pub distribution_port: String,
    /// The request made for "Your own CA", as the helper reports it.
    pub request: Option<RequestState>,
    /// Who signed the intermediate (once added).
    pub signed: Option<String>,
    /// The CA's certificate (once added).
    pub root_added: Option<String>,
}

impl Install {
    pub fn new(hostname: String, home: Option<String>) -> Install {
        Install {
            agent: true,
            assistant: false,
            hostname,
            sans: String::new(),
            ca: Ca::Own,
            root_key_out: super::setup_form::default_root_key(home.as_deref()),
            console_port: ports::CONSOLE_DEFAULT.to_string(),
            ingest_port: ports::INGEST_DEFAULT.to_string(),
            distribution_port: ports::DISTRIBUTION_DEFAULT.to_string(),
            request: None,
            signed: None,
            root_added: None,
        }
    }

    /// The arguments of `setup-plan`.
    pub fn plan_args(&self) -> Vec<String> {
        let mut parts = vec![
            Component::Ingest,
            Component::Console,
            Component::Distribution,
            Component::Vulns,
            Component::Rules,
            Component::Signer,
        ];
        if self.agent {
            parts.push(Component::Agent);
        }
        if self.assistant {
            parts.push(Component::Assistant);
        }
        let names: Vec<&str> = parts.iter().map(|c| c.name()).collect();
        let mut args = vec![
            "--components".into(),
            names.join(","),
            "--hostname".into(),
            self.hostname.trim().into(),
        ];
        for san in self
            .sans
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            args.extend(["--san".into(), san.into()]);
        }
        let ca = if self.ca == Ca::Own {
            "careful"
        } else {
            "quick"
        };
        args.extend(["--ca".into(), ca.into()]);
        if self.ca == Ca::OpenVibes && !self.root_key_out.trim().is_empty() {
            args.extend(["--root-key-out".into(), self.root_key_out.trim().into()]);
        }
        if self.assistant {
            args.extend(["--model".into(), "fetch".into()]);
        }
        args.extend([
            "--console-port".into(),
            self.console_port.trim().into(),
            "--ingest-port".into(),
            self.ingest_port.trim().into(),
            "--distribution-port".into(),
            self.distribution_port.trim().into(),
        ]);
        args
    }

    /// The install as rows: the plan first (inside Packages), then the
    /// steps, the agent and the assistant only when ticked.
    pub fn work(&self) -> Work {
        let one = |title: &str, steps: &[Step]| {
            (
                title.to_owned(),
                steps.iter().map(|s| Call::Setup(*s)).collect::<Vec<_>>(),
            )
        };
        let mut packages = one("Packages", &[Step::Packages]);
        packages.1.insert(0, Call::SetupPlan(self.plan_args()));
        let mut rows = vec![
            packages,
            one("PostgreSQL", &[Step::Postgres]),
            one("Database", &[Step::Operators, Step::Database, Step::Schema]),
            one("Certificate authority", &[Step::Ca]),
            one("Certificates", &[Step::Certificates]),
            one("Console", &[Step::Console]),
            one("Services", &[Step::Services]),
            one("Firewall", &[Step::Firewall]),
            one("Baseline rules", &[Step::Rules]),
        ];
        if self.agent {
            rows.push(one("Agent on this host", &[Step::Agent]));
        }
        rows.push(one("Ready", &[Step::Ready]));
        if self.assistant {
            rows.push(one("Assistant", &[Step::AssistantModel]));
        }
        Work::grouped(Kind::Install, rows)
    }
}
