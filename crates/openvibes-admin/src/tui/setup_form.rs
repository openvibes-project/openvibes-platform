//! The Setup tab's install form: its rows, the plan it writes, the
//! ports it proposes, and #87's filling from a `setup.toml` left by a
//! first install that stopped before its CA.

use platform_host::{Host, ServiceStatus, Unit};

use super::{
    app::{App, Key},
    setup::{
        AGENT_PORTS_ROW, CA_ROW, HOSTNAME_ROW, KEY_ROW, PORT_ROW, Phase, SANS_ROW, START_ROW, Setup,
    },
};
use crate::setup::{
    plan::{CaMode, Component, ModelChoice},
    ports,
};

impl Setup {
    pub fn plan_args(&self) -> Vec<String> {
        let components: Vec<&str> = self.components.iter().map(|c| c.name()).collect();
        let mut args = vec![
            "--components".into(),
            components.join(","),
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
        args.extend([
            "--ca".into(),
            match self.ca {
                CaMode::Quick => "quick",
                CaMode::Careful => "careful",
            }
            .into(),
        ]);
        if self.ca == CaMode::Quick && !self.root_key_out.trim().is_empty() {
            args.extend(["--root-key-out".into(), self.root_key_out.trim().into()]);
        }
        if self.components.contains(&Component::Assistant) {
            args.extend([
                "--model".into(),
                match self.model {
                    ModelChoice::Fetch => "fetch",
                    ModelChoice::Skip => "skip",
                }
                .into(),
            ]);
        }
        args.extend(["--console-port".into(), self.console_port.trim().into()]);
        // Two numbers; anything else goes through as typed, so Setup's own
        // check names what is wrong.
        let mut agent = self.agent_ports.split([',', ' ']).filter(|p| !p.is_empty());
        let ingest = agent.next().unwrap_or("").to_owned();
        let distribution = agent.collect::<Vec<_>>().join(" ");
        args.extend([
            "--ingest-port".into(),
            ingest,
            "--distribution-port".into(),
            distribution,
        ]);
        args
    }

    /// For each port another process holds, proposes the first free one
    /// (from 8443 for the console, 18425 for ingest and distribution) and
    /// notes it on the row. Unprivileged, so the holder is rarely known
    /// here; Setup's own check (as root) names it if it is still there.
    pub fn propose_ports<H: Host>(&mut self, host: &H) {
        let taken = |port: u16| {
            host.listeners(port)
                .map(|lines| ports::parse(&lines).is_some())
                .map_err(|error| error.to_string())
        };
        let defaults = [
            ports::CONSOLE_DEFAULT,
            ports::INGEST_DEFAULT,
            ports::DISTRIBUTION_DEFAULT,
        ];
        let mut chosen: Vec<u16> = defaults.to_vec();
        for (index, from) in [8443, 18425, 18425].into_iter().enumerate() {
            let default = defaults[index];
            // Free, or unknown: Setup checks again before starting.
            let Ok(true) = taken(default) else {
                continue;
            };
            let Ok(port) = ports::suggest(from, |port| Ok(chosen.contains(&port) || taken(port)?))
            else {
                continue;
            };
            chosen[index] = port;
            let note = format!("{default} is in use");
            if index == 0 {
                self.console_note = Some(note);
            } else {
                let joined = self
                    .agent_ports_note
                    .take()
                    .map_or(note.clone(), |n| format!("{n}; {note}"));
                self.agent_ports_note = Some(joined);
            }
        }
        self.console_port = chosen[0].to_string();
        self.agent_ports = format!("{}, {}", chosen[1], chosen[2]);
    }

    /// On a set-up host: a default port another program holds, "443 is in
    /// use" (why the port differs), or, when the plan still has the default
    /// and our unit is not running, "443 is in use by another program": the
    /// user's case, a console crash-looping on a port nginx holds
    /// (reviewer's #106 drive). While our unit runs, the holder is ours.
    pub(super) fn note_taken_defaults<H: Host>(&mut self, host: &H, services: &[ServiceStatus]) {
        let taken = |port: u16| {
            host.listeners(port)
                .is_ok_and(|lines| ports::parse(&lines).is_some())
        };
        let running = |unit: Unit| {
            services
                .iter()
                .any(|status| status.unit == unit && status.active == "active")
        };
        let note = |default: u16, chosen: &str, unit: Unit| {
            let chosen = chosen.trim().parse::<u16>().ok();
            match (chosen == Some(default), taken(default)) {
                (false, true) => Some(format!("{default} is in use")),
                (true, true) if !running(unit) => {
                    Some(format!("{default} is in use by another program"))
                }
                _ => None,
            }
        };
        self.console_note = note(ports::CONSOLE_DEFAULT, &self.console_port, Unit::Console);
        let mut agent: Vec<String> = self
            .agent_ports
            .split([',', ' '])
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect();
        agent.resize(2, String::new());
        let notes: Vec<String> = [
            note(ports::INGEST_DEFAULT, &agent[0], Unit::Ingest),
            note(ports::DISTRIBUTION_DEFAULT, &agent[1], Unit::Distribution),
        ]
        .into_iter()
        .flatten()
        .collect();
        self.agent_ports_note = (!notes.is_empty()).then(|| notes.join("; "));
    }

    pub(super) fn toggle(&mut self, component: Component) {
        use Component::*;
        if component.always() {
            return;
        }
        if !self.components.remove(&component) {
            self.components.insert(component);
            if component == Rules {
                self.components.insert(Distribution);
            }
        } else if component == Distribution {
            self.components.remove(&Rules);
        }
    }

    pub(super) fn field(&mut self) -> Option<&mut String> {
        match self.row {
            HOSTNAME_ROW => Some(&mut self.hostname),
            SANS_ROW => Some(&mut self.sans),
            KEY_ROW => Some(&mut self.root_key_out),
            PORT_ROW => Some(&mut self.console_port),
            AGENT_PORTS_ROW => Some(&mut self.agent_ports),
            _ => None,
        }
    }
}

impl<H: Host> App<H> {
    /// The CA exists: the host's first install got past its CA step.
    pub(super) fn ca_exists(&self) -> bool {
        self.host
            .certificates()
            .iter()
            .any(|(path, _)| *path == "/etc/openvibes/pki/intermediate.crt")
    }

    /// #87 (ruling 6): the install form, filled from the `setup.toml` a
    /// first install that stopped before its CA left. It installs again
    /// (new CA, free root key name), never a Repair, which refuses to make
    /// a CA. A plan that does not parse says so on the form, unfilled.
    pub(super) fn fill_from_plan(&mut self) {
        self.setup.row = 0;
        self.setup.phase = Phase::Form;
        let plan = match self
            .host
            .setup_plan()
            .map_err(|e| e.to_string())
            .and_then(|text| {
                toml::from_str::<crate::setup::plan::Plan>(&text).map_err(|e| e.to_string())
            }) {
            Ok(plan) => plan,
            Err(error) => {
                self.message = Some(error);
                return;
            }
        };
        self.setup.components = plan.components.iter().copied().collect();
        self.setup.hostname = plan.hostname.clone();
        self.setup.sans = plan.sans.join(", ");
        self.setup.ca = plan.ca;
        // Looked up now: a key written since the TUI started (by a CA step
        // that then failed, or kept by Remove everything) is taken.
        self.setup.root_key_out = default_root_key(self.setup.home.as_deref());
        self.setup.console_port = plan.console_port.to_string();
        self.setup.agent_ports = format!("{}, {}", plan.ingest_port, plan.distribution_port);
        self.setup.note_taken_defaults(&self.host, &self.services);
    }

    pub(super) fn form_key(&mut self, key: Key) {
        if self.setup.editing {
            let Some(field) = self.setup.field() else {
                return;
            };
            match key {
                Key::Char(c) if field.len() < 512 => field.push(c),
                Key::Backspace => {
                    field.pop();
                }
                Key::ClearLine => field.clear(),
                Key::Enter | Key::Esc => self.setup.editing = false,
                _ => {}
            }
            return;
        }
        match key {
            Key::Char('j') | Key::Down if self.setup.row < START_ROW => self.setup.row += 1,
            Key::Char('k') | Key::Up => self.setup.row = self.setup.row.saturating_sub(1),
            Key::Char(' ') if self.setup.row < Component::ALL.len() => {
                self.setup.toggle(Component::ALL[self.setup.row])
            }
            Key::Char(' ') | Key::Enter if self.setup.row == CA_ROW => {
                self.setup.ca = match self.setup.ca {
                    CaMode::Quick => CaMode::Careful,
                    CaMode::Careful => CaMode::Quick,
                };
            }
            Key::Enter if self.setup.row == START_ROW => self.start_plan(),
            Key::Enter if self.setup.field().is_some() => self.setup.editing = true,
            Key::Char('q') => self.quit = true,
            _ => {}
        }
    }
}

/// The free default root key file in `home`, or empty without a home.
pub(super) fn default_root_key(home: Option<&str>) -> String {
    home.map(|home| free_root_key(home, |path| std::path::Path::new(path).exists()))
        .unwrap_or_default()
}

/// `HOME/openvibes-root-ca.key`, or `-2`, `-3`… when taken: Remove
/// everything keeps the old root key (it is the user's), so a new install
/// must not stop on it (#87).
fn free_root_key(home: &str, exists: impl Fn(&str) -> bool) -> String {
    super::maint::backup::free_path(&format!("{home}/openvibes-root-ca"), "key", exists)
}

#[cfg(test)]
mod root_key_tests {
    #[test]
    fn the_agent_is_ticked_only_with_the_package_or_a_repository() {
        let dir = std::env::temp_dir().join(format!("ov-agent-default-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc/yum.repos.d")).unwrap();
        std::fs::write(dir.join("etc/yum.repos.d/fedora.repo"), "").unwrap();
        assert!(!crate::setup::agent_by_default(&dir));
        std::fs::write(dir.join("etc/yum.repos.d/openvibes.repo"), "").unwrap();
        assert!(crate::setup::agent_by_default(&dir));
        std::fs::remove_file(dir.join("etc/yum.repos.d/openvibes.repo")).unwrap();
        std::fs::create_dir_all(dir.join("usr/bin")).unwrap();
        std::fs::write(dir.join("usr/bin/openvibes-agent"), "").unwrap();
        assert!(crate::setup::agent_by_default(&dir));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_default_root_key_name_skips_taken_files() {
        let taken = ["/h/openvibes-root-ca.key", "/h/openvibes-root-ca-2.key"];
        assert_eq!(
            super::free_root_key("/h", |p| taken.contains(&p)),
            "/h/openvibes-root-ca-3.key"
        );
        assert_eq!(
            super::free_root_key("/h", |_| false),
            "/h/openvibes-root-ca.key"
        );
    }
}
