//! What Setup installs (admin TUI spec §6.2): `/etc/openvibes/setup.toml`,
//! written by `helper setup-plan` or `setup --quick` from checked arguments,
//! read by every step.

use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::IpAddr,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use clap::ValueEnum;
use platform_host::{SETUP_FILE, Unit};
use serde::{Deserialize, Serialize};

/// A part of the platform Setup can install.
#[derive(
    Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, ValueEnum,
)]
#[serde(rename_all = "kebab-case")]
pub enum Component {
    Ingest,
    Console,
    Distribution,
    Vulns,
    Assistant,
    Rules,
    Agent,
    Signer,
}

impl Component {
    pub const ALL: [Component; 8] = [
        Component::Ingest,
        Component::Console,
        Component::Distribution,
        Component::Vulns,
        Component::Assistant,
        Component::Rules,
        Component::Agent,
        Component::Signer,
    ];

    /// The name `--components` takes.
    pub fn name(self) -> &'static str {
        match self {
            Component::Ingest => "ingest",
            Component::Console => "console",
            Component::Distribution => "distribution",
            Component::Vulns => "vulns",
            Component::Assistant => "assistant",
            Component::Rules => "rules",
            Component::Agent => "agent",
            Component::Signer => "signer",
        }
    }

    /// What it is, for the Setup screen.
    pub fn about(self) -> &'static str {
        match self {
            Component::Ingest => "agent enrollment and findings (always)",
            Component::Console => "web console (always)",
            Component::Distribution => "rules delivered to agents",
            Component::Vulns => "vulnerability feeds and matching",
            Component::Assistant => "local LLM for the console (heavy; needs a model)",
            Component::Rules => "OpenVIBES baseline rules (needs distribution)",
            Component::Agent => "the agent on this host",
            Component::Signer => "signer for your own rules (preview: no console screen yet)",
        }
    }

    /// Its packages.
    pub fn packages(self) -> &'static [&'static str] {
        match self {
            Component::Ingest => &["openvibes-ingest", "openvibes-admin"],
            Component::Console => &["openvibes-console"],
            Component::Distribution => &["openvibes-distribution"],
            Component::Vulns => &["openvibes-vulns"],
            Component::Assistant => &["openvibes-llm"],
            Component::Rules => &["openvibes-rules-baseline"],
            Component::Agent => &["openvibes-agent"],
            Component::Signer => &["openvibes-signer"],
        }
    }

    /// The units Setup enables and starts for it. The assistant's model
    /// server is left stopped: it refuses to start without a model.
    pub fn units(self) -> &'static [Unit] {
        match self {
            Component::Ingest => &[Unit::Ingest, Unit::Maintenance],
            Component::Console => &[Unit::Console],
            Component::Distribution => &[Unit::Distribution],
            Component::Vulns => &[Unit::Vulns],
            Component::Signer => &[Unit::Signer],
            Component::Assistant | Component::Rules | Component::Agent => &[],
        }
    }
}

/// How the CA is created (§6.3 step 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum CaMode {
    /// Root created here, its key written out once, then deleted.
    Quick,
    /// Root stays offline; the intermediate request is signed elsewhere.
    Careful,
}

/// `setup.toml`.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub components: Vec<Component>,
    pub hostname: String,
    #[serde(default)]
    pub sans: Vec<String>,
    pub ca: CaMode,
    #[serde(default)]
    pub root_key_out: Option<PathBuf>,
    #[serde(default)]
    pub admin_password_file: Option<PathBuf>,
    #[serde(default)]
    pub repo_dir: Option<PathBuf>,
    #[serde(default)]
    pub allow_unsigned_local: bool,
    /// The user who ran Setup through sudo; becomes an operator.
    #[serde(default)]
    pub operator: Option<String>,
    /// The console's HTTPS port (plans from before board #45: 443).
    #[serde(default = "console_default")]
    pub console_port: u16,
    /// Ingest's port for agents (plans from before board #48: 18423).
    #[serde(default = "ingest_default")]
    pub ingest_port: u16,
    /// Distribution's port for agents (plans from before board #48: 18424).
    #[serde(default = "distribution_default")]
    pub distribution_port: u16,
}

fn console_default() -> u16 {
    super::ports::CONSOLE_DEFAULT
}

fn ingest_default() -> u16 {
    super::ports::INGEST_DEFAULT
}

fn distribution_default() -> u16 {
    super::ports::DISTRIBUTION_DEFAULT
}

impl Plan {
    /// This plan with the ports given (`setup --repair --console-port N`):
    /// checked like a new plan's, the others kept.
    pub fn with_ports(
        &self,
        console: Option<u16>,
        ingest: Option<u16>,
        distribution: Option<u16>,
    ) -> Result<Plan, String> {
        let mut plan = self.clone();
        plan.console_port = console.unwrap_or(plan.console_port);
        plan.ingest_port = ingest.unwrap_or(plan.ingest_port);
        plan.distribution_port = distribution.unwrap_or(plan.distribution_port);
        super::ports::check_ports(plan.console_port, plan.ingest_port, plan.distribution_port)?;
        Ok(plan)
    }

    pub fn has(&self, component: Component) -> bool {
        self.components.contains(&component)
    }

    /// Names for server certificates: the hostname, the extra names, then
    /// `localhost` and `127.0.0.1` for an agent on this host.
    pub fn names(&self) -> Vec<String> {
        let mut names = vec![self.hostname.clone()];
        for extra in self
            .sans
            .iter()
            .map(String::as_str)
            .chain(["localhost", "127.0.0.1"])
        {
            if !names.iter().any(|name| name == extra) {
                names.push(extra.to_owned());
            }
        }
        names
    }

    fn file(root: &Path) -> PathBuf {
        root.join(SETUP_FILE.trim_start_matches('/'))
    }

    pub fn load(root: &Path) -> Result<Plan, String> {
        Plan::load_filled(root).map(|(plan, _)| plan)
    }

    /// The plan, and whether a port missing from it (a plan from before
    /// the port choices) was taken from the service using it: its default
    /// would move a working service (board #76).
    pub fn load_filled(root: &Path) -> Result<(Plan, bool), String> {
        let path = Plan::file(root);
        let text = fs::read_to_string(&path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => {
                format!("{}: no Setup plan yet (run Setup first)", path.display())
            }
            _ => format!("{}: {error}", path.display()),
        })?;
        let fail = |error: toml::de::Error| format!("{}: {error}", path.display());
        let mut plan: Plan = toml::from_str(&text).map_err(fail)?;
        let table: toml::Table = toml::from_str(&text).map_err(fail)?;
        let mut filled = false;
        let mut fill = |key: &str, port: &mut u16, config: &str, listen: &str| {
            if table.contains_key(key) {
                return;
            }
            let Ok(text) = fs::read_to_string(root.join("etc/openvibes").join(config)) else {
                return;
            };
            let Ok(config) = toml::from_str::<toml::Table>(&text) else {
                return;
            };
            // Behind a proxy the console's listener is not its public port.
            if config.contains_key("transport_mode")
                && config.get("transport_mode").and_then(toml::Value::as_str) != Some("direct_tls")
            {
                return;
            }
            if let Some(used) = config
                .get(listen)
                .and_then(toml::Value::as_str)
                .and_then(|listen| listen.parse::<std::net::SocketAddr>().ok())
            {
                *port = used.port();
                filled = true;
            }
        };
        fill(
            "console_port",
            &mut plan.console_port,
            "console.toml",
            "development_listen",
        );
        fill(
            "ingest_port",
            &mut plan.ingest_port,
            "ingest.toml",
            "listen",
        );
        fill(
            "distribution_port",
            &mut plan.distribution_port,
            "distribution.toml",
            "listen",
        );
        Ok((plan, filled))
    }

    pub fn save(&self, root: &Path) -> Result<(), String> {
        let path = Plan::file(root);
        let dir = path.parent().ok_or("no directory for setup.toml")?;
        let fail = |error: std::io::Error| format!("{}: {error}", path.display());
        fs::create_dir_all(dir).map_err(fail)?;
        let text = toml::to_string(self).map_err(|error| error.to_string())?;
        let temp = dir.join(".setup.toml.new");
        let _ = fs::remove_file(&temp);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp)
            .map_err(fail)?;
        file.write_all(
            format!("# Written by openvibes-admin setup (admin TUI spec §6.2).\n{text}").as_bytes(),
        )
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::rename(&temp, &path))
        .map_err(fail)
    }
}

/// Setup's arguments, shared by `helper setup-plan` and `setup --quick`.
#[derive(clap::Args, Clone, Debug)]
pub struct PlanArgs {
    /// Components, comma-separated: ingest (required), console,
    /// distribution, vulns, assistant, rules, agent, signer.
    #[arg(long, value_delimiter = ',', value_enum)]
    pub components: Vec<Component>,
    /// This host's DNS name, put in the server certificates.
    #[arg(long, default_value = "")]
    pub hostname: String,
    /// More DNS names or IP addresses for the server certificates.
    #[arg(long)]
    pub san: Vec<String>,
    /// quick: root created here; careful: root kept offline.
    #[arg(long, value_enum, default_value = "quick")]
    pub ca: CaMode,
    /// Where the quick CA's root key is written once (e.g. a USB stick);
    /// without it the root key is deleted.
    #[arg(long)]
    pub root_key_out: Option<PathBuf>,
    /// File holding the console admin's password (otherwise generated).
    #[arg(long)]
    pub admin_password_file: Option<PathBuf>,
    /// Install from this folder of package files instead of the repository.
    #[arg(long)]
    pub repo_dir: Option<PathBuf>,
    /// With --repo-dir: accept unsigned package files (test builds only).
    #[arg(long)]
    pub allow_unsigned_local: bool,
    /// The console's HTTPS port (443); Setup refuses one another process
    /// holds. With --repair: move the console there.
    #[arg(long)]
    pub console_port: Option<u16>,
    /// Ingest's port for agents (18423). With --repair: move ingest there.
    #[arg(long)]
    pub ingest_port: Option<u16>,
    /// Distribution's port for agents (18424). With --repair: move it there.
    #[arg(long)]
    pub distribution_port: Option<u16>,
}

/// A lowercase DNS name.
pub fn check_name(name: &str) -> Result<(), String> {
    let label_ok = |label: &str| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    let numeric_top = name
        .rsplit('.')
        .next()
        .is_some_and(|last| !last.is_empty() && last.bytes().all(|b| b.is_ascii_digit()));
    if name.len() <= 253 && name.split('.').all(label_ok) && !numeric_top {
        Ok(())
    } else {
        Err(format!("{name:?} is not a lowercase DNS name"))
    }
}

fn check_san(san: &str) -> Result<(), String> {
    if san.parse::<IpAddr>().is_ok() {
        Ok(())
    } else {
        check_name(san)
    }
}

impl PlanArgs {
    /// The checked plan; `operator` is who ran Setup through sudo.
    pub fn plan(&self, operator: Option<String>) -> Result<Plan, String> {
        if self.components.is_empty() {
            return Err("--components is required".into());
        }
        if self.hostname.is_empty() {
            return Err("--hostname is required".into());
        }
        if self.allow_unsigned_local && self.repo_dir.is_none() {
            return Err("--allow-unsigned-local needs --repo-dir".into());
        }
        if self.root_key_out.is_some() && self.ca == CaMode::Careful {
            return Err(
                "--root-key-out is for the quick CA (a careful CA's root stays offline)".into(),
            );
        }
        let mut components = self.components.clone();
        components.sort();
        components.dedup();
        if !components.contains(&Component::Ingest) {
            return Err("--components must include ingest".into());
        }
        if components.contains(&Component::Rules) && !components.contains(&Component::Distribution)
        {
            return Err("rules need distribution (agents fetch rules from it)".into());
        }
        if components.contains(&Component::Signer)
            && !(components.contains(&Component::Console)
                && components.contains(&Component::Distribution))
        {
            return Err("the signer needs console and distribution (it signs the console's rules for agents to fetch)".into());
        }
        check_name(&self.hostname)?;
        let (console_port, ingest_port, distribution_port) = (
            self.console_port.unwrap_or(super::ports::CONSOLE_DEFAULT),
            self.ingest_port.unwrap_or(super::ports::INGEST_DEFAULT),
            self.distribution_port
                .unwrap_or(super::ports::DISTRIBUTION_DEFAULT),
        );
        super::ports::check_ports(console_port, ingest_port, distribution_port)?;
        if self.san.len() > 16 {
            return Err("at most 16 --san".into());
        }
        for san in &self.san {
            check_san(san)?;
        }
        for path in [
            &self.root_key_out,
            &self.admin_password_file,
            &self.repo_dir,
        ]
        .into_iter()
        .flatten()
        {
            if !path.is_absolute() {
                return Err(format!("{} is not an absolute path", path.display()));
            }
        }
        Ok(Plan {
            components,
            hostname: self.hostname.clone(),
            sans: self.san.clone(),
            ca: self.ca,
            root_key_out: self.root_key_out.clone(),
            admin_password_file: self.admin_password_file.clone(),
            repo_dir: self.repo_dir.clone(),
            allow_unsigned_local: self.allow_unsigned_local,
            operator,
            console_port,
            ingest_port,
            distribution_port,
        })
    }
}

/// The person who ran Setup, from sudo's `SUDO_USER` (not root).
pub fn operator_from_env() -> Option<String> {
    let user = std::env::var("SUDO_USER").ok()?;
    let valid = !user.is_empty()
        && user.len() <= 32
        && user != "root"
        && user.bytes().enumerate().all(|(i, b)| {
            b.is_ascii_lowercase()
                || b == b'_'
                || (i > 0 && (b.is_ascii_digit() || b == b'-' || b == b'.'))
        });
    valid.then_some(user)
}
