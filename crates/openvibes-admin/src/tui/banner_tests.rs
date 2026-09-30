//! The OpenVIBES wordmark and tab line on every screen, at 80×24.

use platform_host::{
    Host, HostError, PackageUpdate, Privileged, Secret, Service, ServiceAction, ServiceStatus, Unit,
};
use ratatui::{Terminal, backend::TestBackend, style::Color};

use super::{
    app::{App, Key, Tab},
    render,
};

struct BannerHost;

impl Host for BannerHost {
    fn services(&self) -> Result<Vec<ServiceStatus>, HostError> {
        Ok(Vec::new())
    }
    fn service_action(&self, _: Unit, _: ServiceAction) -> Result<(), HostError> {
        Ok(())
    }
    fn logs(&self, _: Unit, _: u16) -> Result<Vec<String>, HostError> {
        Ok(Vec::new())
    }
    fn read_config(&self, _: Service) -> Result<String, HostError> {
        Ok(include_str!("../../../../packaging/rpm/ingest.toml").into())
    }
    fn write_config(&self, _: Service, _: &str) -> Result<(), HostError> {
        Ok(())
    }
    fn is_set_up(&self) -> bool {
        false
    }
    fn packages(&self) -> Result<Vec<PackageUpdate>, HostError> {
        Ok(Vec::new())
    }
    fn setup_plan(&self) -> Result<String, HostError> {
        Err(HostError::Failed("not set up".into()))
    }
    fn privileged(&self, _: Privileged<'_>, _: &Secret) -> Result<String, HostError> {
        Ok(String::new())
    }
}

fn app() -> App<BannerHost> {
    let mut app = App::new(BannerHost);
    app.color = true;
    app
}

/// A terminal tall enough for the full wordmark (30 rows or more).
fn draw(app: &App<BannerHost>) -> Terminal<TestBackend> {
    draw_at(app, 36)
}

fn draw_at(app: &App<BannerHost>, height: u16) -> Terminal<TestBackend> {
    let mut terminal = Terminal::new(TestBackend::new(80, height)).unwrap();
    terminal.draw(|frame| render(frame, app)).unwrap();
    terminal
}

fn rows(app: &App<BannerHost>) -> Vec<String> {
    rows_at(app, 36)
}

fn rows_at(app: &App<BannerHost>, height: u16) -> Vec<String> {
    let terminal = draw_at(app, height);
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect()
        })
        .collect()
}

#[test]
fn the_wordmark_and_tabs_head_every_screen() {
    let mut app = app();
    for (tab, current) in [
        (Tab::Setup, "[Setup]"),
        (Tab::Services, "[Services]"),
        (Tab::Configuration, "[Configuration]"),
    ] {
        app.tab = tab;
        let rows = rows(&app);
        // "Open" then "VIBES" in figlet's standard font, one space apart.
        assert!(
            rows[0].contains("___") && rows[0].contains("__     _____ ____  _____ ____"),
            "{rows:#?}"
        );
        assert!(rows[4].contains(r"\___/| .__/ \___|_| |_|"), "{rows:#?}");
        assert!(
            rows[4].contains(r"\_/  |___|____/|_____|____/"),
            "{rows:#?}"
        );
        assert!(rows[5].contains("|_|"), "the p's descender: {rows:#?}");
        assert!(rows[5].contains(current), "{tab:?}: {:?}", rows[5]);
        assert!(
            rows[..6]
                .iter()
                .any(|r| r.contains(concat!("v", env!("CARGO_PKG_VERSION")))),
            "{rows:#?}"
        );
    }
}

#[test]
fn open_is_white_and_vibes_teal_unless_no_color() {
    let mut app = app();
    let terminal = draw(&app);
    let buffer = terminal.backend().buffer();
    // Row 1: " / _ \ …" starts "Open"; "\ \   / /" starts "VIBES" after it.
    let open = (0..30).find(|x| buffer[(*x, 1)].symbol() == "/").unwrap();
    let vibes = (open + 20..80)
        .find(|x| buffer[(*x, 1)].symbol() == r"\")
        .unwrap();
    assert_eq!(buffer[(open, 1)].fg, Color::White);
    assert_eq!(buffer[(vibes, 1)].fg, super::banner::TEAL);
    app.color = false;
    let terminal = draw(&app);
    let buffer = terminal.backend().buffer();
    assert_eq!(buffer[(open, 1)].fg, Color::Reset);
    assert_eq!(buffer[(vibes, 1)].fg, Color::Reset);
}

#[test]
fn the_selected_field_stays_visible_in_a_long_form() {
    let mut app = app();
    app.tab = Tab::Services;
    app.key(Key::Tab);
    assert_eq!(app.tab, Tab::Configuration);
    let last = app
        .config
        .form
        .as_ref()
        .unwrap()
        .fields()
        .last()
        .unwrap()
        .key;
    for _ in 0..60 {
        app.key(Key::Down);
    }
    let rows = rows(&app);
    assert!(
        rows.iter().any(|r| r.contains(last)),
        "{last} not shown:\n{rows:#?}"
    );
}

/// Board #78: at 80x24 the six-row wordmark took a quarter of the screen;
/// below 30 rows it is one line with the same tabs and version.
#[test]
fn a_short_terminal_gets_a_one_line_banner() {
    let mut app = app();
    app.tab = Tab::Services;
    let rows = rows_at(&app, 24);
    assert!(rows[0].contains("OpenVIBES"), "{rows:#?}");
    assert!(rows[0].contains("[Services]"), "{rows:#?}");
    assert!(
        rows[0].contains(concat!("v", env!("CARGO_PKG_VERSION"))),
        "{rows:#?}"
    );
    assert!(
        !rows.iter().any(|r| r.contains("___")),
        "no wordmark: {rows:#?}"
    );
    // The screen below starts on the second row.
    assert!(!rows[1].trim().is_empty(), "{rows:#?}");
}

#[test]
fn the_short_banner_keeps_the_colours() {
    let app = app();
    let terminal = draw_at(&app, 24);
    let buffer = terminal.backend().buffer();
    let at = |text: &str| {
        let row: String = (0..80).map(|x| buffer[(x, 0)].symbol()).collect();
        u16::try_from(row.find(text).unwrap()).unwrap()
    };
    assert_eq!(buffer[(at("Open"), 0)].fg, Color::White);
    assert_eq!(buffer[(at("VIBES"), 0)].fg, super::banner::TEAL);
}
