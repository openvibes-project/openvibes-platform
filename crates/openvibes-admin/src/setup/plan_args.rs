//! A plan as `helper setup-plan` arguments, and the round trip's tests.

use super::plan::{CaMode, ModelChoice, Plan};

impl Plan {
    /// The arguments that rebuild this plan: `setup-plan` replaces the
    /// whole plan, so every field is passed (only `operator` comes from
    /// SUDO_USER). The root key file is passed as saved: the helper only
    /// checks that it is an absolute path; whether the file exists is
    /// the CA step's concern, as for the plan already on disk.
    pub fn args(&self) -> Vec<String> {
        let components: Vec<_> = self.components.iter().map(|c| c.name()).collect();
        let mut args = vec![
            "--components".to_owned(),
            components.join(","),
            "--hostname".into(),
            self.hostname.clone(),
        ];
        for san in &self.sans {
            args.extend(["--san".into(), san.clone()]);
        }
        let ca = match self.ca {
            CaMode::Quick => "quick",
            CaMode::Careful => "careful",
            CaMode::Import => "import",
        };
        args.extend(["--ca".into(), ca.into()]);
        let mut path = |flag: &str, value: &Option<std::path::PathBuf>| {
            if let Some(value) = value {
                args.extend([flag.to_owned(), value.display().to_string()]);
            }
        };
        if self.ca == CaMode::Quick {
            path("--root-key-out", &self.root_key_out);
        }
        path("--admin-password-file", &self.admin_password_file);
        path("--repo-dir", &self.repo_dir);
        if self.allow_unsigned_local {
            args.push("--allow-unsigned-local".into());
        }
        args.extend([
            "--console-port".into(),
            self.console_port.to_string(),
            "--ingest-port".into(),
            self.ingest_port.to_string(),
            "--distribution-port".into(),
            self.distribution_port.to_string(),
            "--model".into(),
            match self.model {
                ModelChoice::Fetch => "fetch",
                ModelChoice::Skip => "skip",
            }
            .into(),
        ]);
        args
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::super::plan::{CaMode, Component, ModelChoice, Plan, PlanArgs};

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        plan: PlanArgs,
    }

    fn full() -> Plan {
        Plan {
            components: vec![Component::Ingest, Component::Console, Component::Assistant],
            hostname: "limebox.lan".into(),
            sans: vec!["10.0.0.5".into(), "box.lan".into()],
            ca: CaMode::Quick,
            root_key_out: Some("/media/usb/root.key".into()),
            admin_password_file: Some("/root/admin.pw".into()),
            repo_dir: Some("/srv/pkgs".into()),
            allow_unsigned_local: true,
            operator: Some("alice".into()),
            console_port: 8443,
            ingest_port: 18500,
            distribution_port: 18501,
            model: ModelChoice::Fetch,
        }
    }

    fn back(plan: &Plan) -> Plan {
        let argv = std::iter::once("setup-plan".to_owned()).chain(plan.args());
        Cli::try_parse_from(argv)
            .unwrap()
            .plan
            .plan(plan.operator.clone())
            .unwrap()
    }

    #[test]
    fn every_field_survives_the_round_trip() {
        let plan = full();
        assert_eq!(back(&plan), plan);
    }

    #[test]
    fn a_careful_plan_passes_no_root_key() {
        let plan = Plan {
            ca: CaMode::Careful,
            root_key_out: None,
            ..full()
        };
        assert!(!plan.args().contains(&"--root-key-out".to_owned()));
        assert_eq!(back(&plan), plan);
    }

    #[test]
    fn an_import_plan_survives_the_round_trip() {
        let plan = Plan {
            ca: CaMode::Import,
            root_key_out: None,
            ..full()
        };
        assert!(plan.args().contains(&"import".to_owned()));
        assert_eq!(back(&plan), plan);
    }

    #[test]
    fn an_imported_ca_takes_no_root_key_file() {
        let argv = [
            "setup-plan",
            "--components",
            "ingest",
            "--hostname",
            "h.lan",
            "--ca",
            "import",
            "--root-key-out",
            "/media/usb/root.key",
        ];
        let error = Cli::try_parse_from(argv)
            .unwrap()
            .plan
            .plan(None)
            .unwrap_err();
        assert!(
            error.contains("--root-key-out is for the quick CA"),
            "{error}"
        );
    }
}
