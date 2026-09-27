//! Process-level guards: the configuration file and the loopback-only
//! listeners.

use std::path::PathBuf;

use openvibes_console::{ConsoleError, load_config, run};
use tokio::net::TcpListener;

fn scratch(name: &str, text: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("console-config");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

#[test]
fn the_configuration_is_strict_and_loopback_only() {
    let good = "development_listen = \"127.0.0.1:18490\"\nhealth_listen = \"127.0.0.1:18491\"\n";
    let config = load_config(&scratch("good.toml", good)).unwrap();
    assert_eq!(config.development_listen.port(), 18490);
    for (name, text) in [
        ("unknown-key", format!("{good}listn = \"x\"\n")),
        ("public", good.replace("127.0.0.1:18490", "0.0.0.0:18490")),
        (
            "same-port",
            good.replace("127.0.0.1:18491", "127.0.0.1:18490"),
        ),
        ("not-toml", "development_listen = ".to_owned()),
    ] {
        assert!(
            matches!(
                load_config(&scratch(&format!("{name}.toml"), &text)),
                Err(ConsoleError::Config)
            ),
            "{name}"
        );
    }
    assert!(matches!(
        load_config(std::path::Path::new("/nonexistent/console.toml")),
        Err(ConsoleError::Config)
    ));
}

#[tokio::test]
async fn a_non_loopback_listener_is_refused_before_serving() {
    let public = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let health = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let result = run(public, health, std::future::pending()).await;
    assert!(matches!(result, Err(ConsoleError::Config)));
}
