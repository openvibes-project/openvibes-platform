//! The Install screens (sub-project 3; install.py, full_advanced.py): the
//! choices in `Install`, the plan they write, and the work that runs it.
//! Installing and Finished are in `run.rs` and `finished.rs`; the five
//! steps in `steps.rs`, `certs.rs`, `paste.rs` and `import.rs`. The install
//! runs on the worker like every other long job.

mod certs;
pub(super) mod fields;
pub(crate) mod finished;
mod import;
mod import_paste;
mod paste;
mod quick;
mod review;
mod run;
pub(super) mod steps;
mod welcome;
pub(super) use run::draw;
#[cfg(test)]
mod certs_accept_tests;
#[cfg(test)]
mod certs_chain_tests;
#[cfg(test)]
mod certs_file_tests;
#[cfg(test)]
mod certs_tests;
#[cfg(test)]
mod import_file_tests;
#[cfg(test)]
mod import_tests;
#[cfg(test)]
mod quick_tests;
#[cfg(test)]
mod run_tests;
#[cfg(test)]
mod steps_tests;

use platform_host::Step;

pub use import::{Imported, Locked};

use super::{
    maint::folder::Browse,
    password::PasswordPrompt,
    run::{Call, Kind, Work},
};
use crate::setup::{plan::Component, ports, request::RequestState};

/// Who signs the platform's CA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ca {
    /// Your own CA signs the intermediate (`--ca careful`).
    Own,
    /// A finished intermediate and its key from your PKI (`--ca import`).
    Import,
    /// OpenVIBES makes its own root (`--ca quick`).
    OpenVibes,
}

/// The two certificates "Your own CA" adds, and the certificate and key
/// Import from your PKI adds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Which {
    Signed,
    Root,
    Cert,
    Key,
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
    /// Why a default port moved ("443 is in use by nginx: the console uses 8443").
    pub port_note: Option<String>,
    /// The text of the field being edited in place, as it was.
    pub editing: Option<String>,
    /// The request made for "Your own CA", as the helper reports it.
    pub request: Option<RequestState>,
    /// Who signed the intermediate (once added).
    pub signed: Option<String>,
    /// The CA's certificate (once added): its name.
    pub root_added: Option<String>,
    /// The operator's home: the root key and the request's copy go there.
    pub home: Option<String>,
    /// Where Esc returns after a failed install: Quick or Review.
    pub origin: Stage,
    /// Each port moved off its default (console, ingest, distribution),
    /// and why: "443 is in use by nginx", until Enter keeps the proposal.
    pub proposed: [Option<String>; 3],
    /// Where the helper saved the request's copy, as it said.
    pub copy: Option<String>,
    /// The signed certificate added and its issuer, until the helper keeps it.
    pub cert: Option<(String, String)>,
    /// Your CA's certificate added, until the helper keeps it.
    pub root_pem: Option<String>,
    /// The paste box's text, while it is open.
    pub paste: Option<String>,
    /// The name of the file the box's text was read from; `None` when
    /// pasted.
    pub paste_file: Option<String>,
    /// The file browser of "From a file on this host", while it is open.
    pub pick: Option<Browse>,
    /// Why the helper refused the request or the certificates (or why a
    /// #87 plan did not read).
    pub error: Option<String>,
    /// What the line under Ports says of the port being typed.
    pub port_check: Option<Result<String, String>>,
    /// Import from your PKI: the chain and key added, until the helper
    /// keeps them.
    pub imported: Option<Imported>,
    /// The password typed in the bar for `locked` (not sudo's).
    pub secret: Option<PasswordPrompt>,
    /// What "Its password" opens: a .p12 file's bytes, or a locked key.
    pub locked: Option<Locked>,
    /// The PKCS#8 key the box's locked key opened to, until Use it or Esc.
    pub unlocked: Option<zeroize::Zeroizing<String>>,
    /// The helper's `imported` line once it kept the import: Next goes on.
    pub import_done: Option<String>,
}

impl Install {
    pub fn new(hostname: String, home: Option<String>) -> Install {
        Install {
            agent: true,
            assistant: false,
            hostname,
            sans: String::new(),
            ca: Ca::Own,
            root_key_out: fields::default_root_key(home.as_deref()),
            home,
            origin: Stage::Step(4),
            proposed: [None, None, None],
            copy: None,
            cert: None,
            root_pem: None,
            paste: None,
            paste_file: None,
            pick: None,
            error: None,
            port_check: None,
            imported: None,
            secret: None,
            locked: None,
            unlocked: None,
            import_done: None,
            console_port: ports::CONSOLE_DEFAULT.to_string(),
            ingest_port: ports::INGEST_DEFAULT.to_string(),
            distribution_port: ports::DISTRIBUTION_DEFAULT.to_string(),
            port_note: None,
            editing: None,
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
        let ca = match self.ca {
            Ca::Own => "careful",
            Ca::Import => "import",
            Ca::OpenVibes => "quick",
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

/// The location line after the host name.
pub(super) fn location(stage: Stage) -> String {
    let certs = " · Install › Certificates ›";
    match stage {
        Stage::Quick => " · Install › Quick install".into(),
        Stage::Step(at) => format!(" · Install › {}", steps::STEPS[usize::from(at.min(4))]),
        Stage::Request => format!("{certs} Request"),
        Stage::Add(Which::Signed) => format!("{certs} Signed certificate"),
        Stage::Add(Which::Root) => format!("{certs} Your CA's certificate"),
        Stage::Add(Which::Cert) => format!("{certs} Certificate"),
        Stage::Add(Which::Key) => format!("{certs} Private key"),
        Stage::Welcome | Stage::Running | Stage::Finished => " · Install".into(),
    }
}

/// Install's help line: the password clause only when sudo asks one.
pub(super) fn install_help(needs_password: bool) -> &'static str {
    if needs_password {
        "Starts the install; it asks for your password once."
    } else {
        "Starts the install."
    }
}
