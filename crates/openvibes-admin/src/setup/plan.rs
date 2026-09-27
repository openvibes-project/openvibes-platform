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
}

impl Component {
    pub const ALL: [Component; 7] = [
        Component::Ingest,
        Component::Console,
        Component::Distribution,
        Component::Vulns,
        Component::Assistant,
        Component::Rules,
        Component::Agent,
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
}

impl Plan {
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
        let path = Plan::file(root);
        let text = fs::read_to_string(&path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => {
                format!("{}: no Setup plan yet (run Setup first)", path.display())
            }
            _ => format!("{}: {error}", path.display()),
        })?;
        toml::from_str(&text).map_err(|error| format!("{}: {error}", path.display()))
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
    /// distribution, vulns, assistant, rules, agent.
    #[arg(long, value_delimiter = ',', required = true, value_enum)]
    pub components: Vec<Component>,
    /// This host's DNS name, put in the server certificates.
    #[arg(long)]
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
        check_name(&self.hostname)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(components: &[Component], hostname: &str, sans: &[&str]) -> PlanArgs {
        PlanArgs {
            components: components.to_vec(),
            hostname: hostname.into(),
            san: sans.iter().map(|s| (*s).to_owned()).collect(),
            ca: CaMode::Quick,
            root_key_out: None,
            admin_password_file: None,
            repo_dir: None,
            allow_unsigned_local: false,
        }
    }

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ov-plan-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_plan_is_sorted_saved_and_loaded() {
        use Component::*;
        let plan = args(
            &[Agent, Ingest, Vulns, Ingest],
            "platform.example.com",
            &["10.0.0.5"],
        )
        .plan(Some("alice".into()))
        .unwrap();
        assert_eq!(plan.components, [Ingest, Vulns, Agent]);
        assert_eq!(
            plan.names(),
            ["platform.example.com", "10.0.0.5", "localhost", "127.0.0.1"]
        );
        let root = temp("roundtrip");
        plan.save(&root).unwrap();
        let file = root.join("etc/openvibes/setup.toml");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(Plan::load(&root).unwrap(), plan);
        std::fs::write(
            &file,
            "components = [\"ingest\"]\nhostname = \"a\"\nca = \"quick\"\nextra = 1\n",
        )
        .unwrap();
        assert!(Plan::load(&root).is_err(), "unknown fields are refused");
    }

    #[test]
    fn bad_plans_are_refused() {
        use Component::*;
        let host = "platform.example.com";
        for (args, want) in [
            (args(&[Console], host, &[]), "must include ingest"),
            (args(&[Ingest, Rules], host, &[]), "rules need distribution"),
            (
                args(&[Ingest], "Platform.example.com", &[]),
                "lowercase DNS name",
            ),
            (
                args(&[Ingest], "platform..example.com", &[]),
                "lowercase DNS name",
            ),
            (
                args(&[Ingest], "-platform.example.com", &[]),
                "lowercase DNS name",
            ),
            (
                args(&[Ingest], "platform.example.com.", &[]),
                "lowercase DNS name",
            ),
            (args(&[Ingest], "1.2.3", &[]), "lowercase DNS name"),
            (args(&[Ingest], host, &["bad name"]), "lowercase DNS name"),
            (args(&[Ingest], host, &["a"; 17]), "at most 16"),
        ] {
            let error = args.plan(None).unwrap_err();
            assert!(error.contains(want), "{error} should contain {want}");
        }
        let mut relative = args(&[Ingest], host, &[]);
        relative.root_key_out = Some("root.key".into());
        assert!(
            relative
                .plan(None)
                .unwrap_err()
                .contains("not an absolute path")
        );
        assert!(
            args(&[Ingest], host, &["10.0.0.5", "fd00::5", "ingest.lan"])
                .plan(None)
                .is_ok()
        );
    }

    #[test]
    fn every_component_names_its_packages() {
        for component in Component::ALL {
            assert!(!component.packages().is_empty(), "{component:?}");
            assert!(
                component
                    .packages()
                    .iter()
                    .all(|p| p.starts_with("openvibes-"))
            );
        }
        assert_eq!(
            Component::Ingest.packages(),
            ["openvibes-ingest", "openvibes-admin"]
        );
        assert_eq!(Component::Ingest.units(), [Unit::Ingest, Unit::Maintenance]);
    }
}
