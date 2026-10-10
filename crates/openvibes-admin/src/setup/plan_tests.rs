//! Setup plan arguments and the plan file.

use std::path::PathBuf;

use platform_host::Unit;

use super::plan::*;

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
        console_port: None,
        ingest_port: None,
        distribution_port: None,
        model: None,
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
            args(&[Ingest, Console, Signer], host, &[]),
            "signer needs console and distribution",
        ),
        (
            args(&[Ingest, Distribution, Signer], host, &[]),
            "signer needs console and distribution",
        ),
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
        (args(&[], host, &[]), "--components is required"),
        (args(&[Ingest], "", &[]), "--hostname is required"),
    ] {
        let error = args.plan(None).unwrap_err();
        assert!(error.contains(want), "{error} should contain {want}");
    }
    let mut unsigned = args(&[Ingest], host, &[]);
    unsigned.allow_unsigned_local = true;
    assert!(
        unsigned
            .plan(None)
            .unwrap_err()
            .contains("needs --repo-dir")
    );
    let mut careful = args(&[Ingest], host, &[]);
    careful.ca = CaMode::Careful;
    careful.root_key_out = Some("/media/usb/root.key".into());
    assert!(careful.plan(None).unwrap_err().contains("quick CA"));
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
    assert_eq!(
        Component::Ingest.units(),
        [Unit::Ingest, Unit::Maintenance, Unit::Netlog]
    );
}

#[test]
fn repair_moves_only_the_ports_it_is_given() {
    let plan = super::fake::plan(&[Component::Ingest, Component::Console]);
    let moved = plan.with_ports(Some(8444), None, None).unwrap();
    assert_eq!(
        (
            moved.console_port,
            moved.ingest_port,
            moved.distribution_port
        ),
        (8444, 18423, 18424)
    );
    assert_eq!(moved.hostname, plan.hostname);
    // Checked like a new plan's.
    assert!(
        plan.with_ports(None, Some(18424), None)
            .unwrap_err()
            .contains("must differ")
    );
    assert!(plan.with_ports(Some(18430), None, None).is_err());
}

/// A plan from before the port choices (0.1.1): no port fields.
const OLD_PLAN: &str = "components = [\"ingest\", \"console\", \"distribution\"]\n\
                        hostname = \"metabox-lnx\"\nca = \"quick\"\n";

fn old_host(name: &str) -> PathBuf {
    let root = temp(name);
    let etc = root.join("etc/openvibes");
    std::fs::create_dir_all(&etc).unwrap();
    std::fs::write(etc.join("setup.toml"), OLD_PLAN).unwrap();
    root
}

/// Board #76: Repair on such a host moved a working 8443 console back to
/// 443, then stopped on "443 is taken". The ports the services really use
/// fill the missing fields instead.
#[test]
fn a_plan_without_ports_takes_the_ones_the_services_use() {
    let root = old_host("old-ports");
    let etc = root.join("etc/openvibes");
    std::fs::write(
        etc.join("console.toml"),
        "transport_mode = \"direct_tls\"\ndevelopment_listen = \"0.0.0.0:8443\"\n",
    )
    .unwrap();
    std::fs::write(etc.join("ingest.toml"), "listen = \"[::]:18500\"\n").unwrap();
    let (plan, filled) = Plan::load_filled(&root).unwrap();
    assert!(filled);
    assert_eq!(
        (plan.console_port, plan.ingest_port, plan.distribution_port),
        (8443, 18500, 18424),
        "no distribution.toml: its default"
    );
    assert_eq!(Plan::load(&root).unwrap(), plan);
}

#[test]
fn saved_ports_win_and_a_proxied_console_keeps_its_default() {
    let root = old_host("saved-ports");
    let etc = root.join("etc/openvibes");
    std::fs::write(
        etc.join("console.toml"),
        "transport_mode = \"reverse_proxy\"\ndevelopment_listen = \"127.0.0.1:8080\"\n",
    )
    .unwrap();
    let (plan, _) = Plan::load_filled(&root).unwrap();
    assert_eq!(
        plan.console_port, 443,
        "behind a proxy the listener is not the port"
    );
    std::fs::write(
        etc.join("setup.toml"),
        format!("{OLD_PLAN}console_port = 9443\ningest_port = 18423\ndistribution_port = 18424\n"),
    )
    .unwrap();
    std::fs::write(etc.join("ingest.toml"), "listen = \"0.0.0.0:18500\"\n").unwrap();
    let (plan, filled) = Plan::load_filled(&root).unwrap();
    assert!(!filled);
    assert_eq!((plan.console_port, plan.ingest_port), (9443, 18423));
}

#[test]
fn the_model_is_fetched_by_default_with_the_assistant_and_skip_leaves_it_out() {
    use Component::*;
    let plan = args(&[Ingest, Assistant], "p.example.com", &[])
        .plan(None)
        .unwrap();
    assert_eq!(plan.model, ModelChoice::Fetch);
    let mut skip = args(&[Ingest, Assistant], "p.example.com", &[]);
    skip.model = Some(ModelChoice::Skip);
    assert_eq!(skip.plan(None).unwrap().model, ModelChoice::Skip);
    let none = args(&[Ingest], "p.example.com", &[]).plan(None).unwrap();
    assert_eq!(none.model, ModelChoice::Skip);
}
