//! Maintenance › Certificates › Replace, key by key (certs2.py #3-4,
//! certs4a.py #2-10): your own CA's request and paste; the root key file
//! when OpenVIBES made the CA; the question, the password, the steps.

use chrono::{Duration, Utc};
use platform_host::HostError;
use platform_pki::{generate_root, intermediate_request, sign_intermediate};

use super::{
    certs_page_tests::{day, framed, keys, menu, ours, page_body, put},
    certs_tests::{app_with, pki, plan_text},
};
use crate::{
    setup::replace::PROGRESS,
    tui::{
        app::{App, Key},
        install::{Stage, Which},
        maint::Page,
        nav::Screen,
        script_host::{SetupHost, body, screen, type_text},
    },
};

const ROOT: &str = "/etc/openvibes/pki/root.crt";
const NOTE: &str = "    Needs the root key kept offline at install. Nothing changes until Replace.";
const STEPS: [&str; 4] = [
    "Making the new intermediate",
    "Trusting the old and the new one",
    "Issuing the server certificates",
    "Restarting the services",
];

fn calls(app: &App<SetupHost>) -> Vec<String> {
    app.host
        .calls
        .borrow()
        .iter()
        .map(|c| c.0.clone())
        .collect()
}

/// What `ca-replace` prints: the stages from `first`, then the dates
/// (the old intermediate trusted 31 days: 30 client days and one).
fn replaced(first: usize) -> Result<String, HostError> {
    let mut out: String = STEPS[first..].iter().map(|s| format!("{s}\n")).collect();
    out.push_str(&format!("done\t{}\t{}\n", day(1460), day(31)));
    Ok(out)
}

/// The Replace screen of certs4a.py: the note, `rows`, then `line`.
fn quick_body(rows: &[(&str, String)], row: usize, line: &str, bar: &str) -> String {
    let mut lines = vec![NOTE.to_owned(), String::new()];
    lines.extend(menu(rows, row));
    if !line.is_empty() {
        lines.extend([String::new(), format!("    {line}")]);
    }
    framed("Replace the intermediate", lines, bar)
}

/// The step list when every step is done, and the result line.
fn done_body(steps: &[&str], result: &str) -> String {
    let mut lines: Vec<String> = steps.iter().map(|s| format!("    ✓ {s}")).collect();
    lines.extend([String::new(), format!("    ✓ {result}")]);
    framed("Replacing the intermediate", lines, "  Enter  Back")
}

#[test]
fn replace_quick_wrong_key_then_right_key_then_runs() {
    let (pems, root) = pki(10);
    let mut app = app_with(pems.clone());
    put(&app, ROOT, &root.cert_pem);
    put(&app, "/media/usb/openvibes-root.key", &root.key_pem);
    let other = generate_root(Utc::now()).unwrap();
    put(&app, "/media/usb/other.key", &other.key_pem);
    let usb = app.root.join("media/usb");
    app.install.home = Some(usb.display().to_string());
    app.host.answers.borrow_mut().push_back(replaced(0));
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    let empty = [
        ("Root key file", "not added yet".to_owned()),
        ("Replace", "once the root key file is added".into()),
    ];
    assert_eq!(
        body(&app),
        quick_body(&empty, 0, "", &keys("Pick the file"))
    );

    // The file browser: .., openvibes-root.key, other.key.
    app.key(Key::Enter);
    assert!(screen(&app).contains("Choose a file"), "{}", screen(&app));
    app.key(Key::Down);
    app.key(Key::Down);
    app.key(Key::Enter);
    let wrong = [
        ("Root key file", "✗ ~/other.key".to_owned()),
        ("Replace", "once the root key file is added".into()),
    ];
    let red = "✗ Not the key of this host's root: pick the root key kept at install.";
    assert_eq!(
        body(&app),
        quick_body(&wrong, 0, red, &keys("Pick another file"))
    );
    // Replace does nothing yet.
    app.key(Key::Down);
    app.key(Key::Enter);
    assert!(app.question.is_none());

    app.key(Key::Up);
    app.key(Key::Enter);
    app.key(Key::Down);
    app.key(Key::Enter);
    let key = usb.join("openvibes-root.key").display().to_string();
    let right = [
        ("Root key file", "✓ ~/openvibes-root.key".to_owned()),
        ("Replace", "a new intermediate, signed here".into()),
    ];
    let green = "✓ The key matches the OpenVIBES root on this host.";
    assert_eq!(body(&app), quick_body(&right, 1, green, &keys("Replace")));

    app.key(Key::Enter);
    assert!(app.question.as_ref().is_some_and(|(_, yes)| *yes));
    // Ruling 10: short enough for rule 30's buttons.
    let text = screen(&app);
    assert!(
        text.contains("│ Replace it? agents keep working") && text.contains("[ Yes ]  No"),
        "{text}"
    );
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    let text = screen(&app);
    assert!(
        text.contains("│ Your password (sudo): **█") && text.contains("Enter  Replace"),
        "{text}"
    );
    assert!(text.contains("Esc  Cancel"), "{text}");
    app.key(Key::Enter);
    assert_eq!(calls(&app), [format!("ca-replace --root-key {key}")]);
    let done = "Replaced · agents move over in 30 days · put the key offline again (0 s)";
    assert_eq!(body(&app), done_body(&STEPS, done));

    // Back on the page, the old intermediate is still trusted.
    let until = Utc::now() + Duration::days(31);
    put(&app, "/etc/openvibes/pki/previous.crt", &pems[1].1);
    put(
        &app,
        "/etc/openvibes/pki/previous-until",
        &until.to_rfc3339(),
    );
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Certificates));
    let date = until.format("%Y-%m-%d").to_string();
    assert_eq!(body(&app), page_body(&ours(&pems, Some(&date)), true, 0));
}

/// Your own CA's page with the request made (the password given).
fn own_ca() -> (App<SetupHost>, String, String) {
    let (pems, _) = pki(10);
    let now = Utc::now();
    let root = generate_root(now).unwrap();
    let (csr, _key) = intermediate_request().unwrap();
    let cert = sign_intermediate(&root, &csr, now).unwrap();
    let mut app = app_with(pems);
    app.host.plan = plan_text().replace("quick", "careful");
    put(&app, ROOT, &root.cert_pem);
    app.host.answers.borrow_mut().extend([
        Ok(format!("request\n{csr}")),
        Ok(format!("signed\tOpenVIBES Root CA\n{csr}")),
        replaced(1),
    ]);
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    (app, cert, root.cert_pem)
}

#[test]
fn replace_own_ca_paste_then_replace() {
    let (mut app, cert, root) = own_ca();
    assert!(
        calls(&app)[0].starts_with("ca-request"),
        "{:?}",
        calls(&app)
    );
    let rows = |signed: &str, replace: &str| {
        [
            ("Show the request", "to copy it to your CA".to_owned()),
            ("Signed certificate", signed.to_owned()),
            ("Your CA's certificate", "✓ OpenVIBES Root CA (kept)".into()),
            ("Replace", replace.to_owned()),
        ]
    };
    let mut lines = vec![
        "    The same steps as at install. Nothing changes until Replace.".to_owned(),
        String::new(),
    ];
    lines.extend(menu(
        &rows("not added yet", "once the signed certificate is added"),
        1,
    ));
    let want = framed(
        "Replace the intermediate",
        lines,
        &keys("Add the signed certificate"),
    );
    assert_eq!(body(&app), want);

    // The install's two ways, then its paste box, checked at once.
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Signed)));
    app.key(Key::Enter);
    app.key(Key::Paste(cert.clone()));
    let text = screen(&app);
    for want in [
        "Paste the signed certificate",
        "✓ Intermediate for limebox.lan · signed by OpenVIBES Root CA",
        "✓ Matches the request · valid until",
        "Enter  Use it",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    assert_eq!(
        calls(&app)[1],
        format!(
            "ca-accept --cert {} --root-cert {}",
            cert.trim(),
            root.trim()
        )
    );
    let text = screen(&app);
    assert!(
        text.contains("✓ added · signed by OpenVIBES Root CA")
            && text.contains("▸ Replace                    a new intermediate from your CA")
            && text.contains("Enter  Replace"),
        "{text}"
    );

    app.key(Key::Enter);
    assert!(app.question.as_ref().is_some_and(|(_, yes)| *yes));
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    assert_eq!(calls(&app)[2], "ca-replace");
    let done = "Replaced · agents move over in 30 days (0 s)";
    assert_eq!(body(&app), done_body(&STEPS[1..], done));
}

#[test]
fn esc_on_replace_changes_nothing() {
    let (mut app, _, _) = own_ca();
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Certificates));
    let made = calls(&app);
    assert!(
        made.len() == 1 && made[0].starts_with("ca-request"),
        "{made:?}"
    );

    let (pems, root) = pki(10);
    let mut app = app_with(pems);
    put(&app, ROOT, &root.cert_pem);
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Certificates));
    assert!(calls(&app).is_empty());
}

#[test]
fn a_refused_replace_says_why() {
    let (mut app, _, _) = own_ca();
    let why = "openvibes-admin helper: There is no signed request: make the request and add \
               both certificates first.";
    app.install.request = Some(crate::setup::request::RequestState::Signed {
        csr: String::new(),
        issuer: "OpenVIBES Root CA".into(),
    });
    app.host.answers.borrow_mut().clear();
    app.host
        .answers
        .borrow_mut()
        .push_back(Err(HostError::Failed(why.into())));
    app.nav.row = 3;
    app.key(Key::Enter);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    let text = screen(&app);
    assert!(
        text.contains("    ✗ There is no signed request: make the request and add both")
            && text.contains("    ✗ Trusting the old and the new one")
            && text.contains("Enter  Back"),
        "{text}"
    );
}

/// Quick, the right root key picked, then Replace, Yes and the password.
fn quick_replacing(answer: Option<Result<String, HostError>>, progress: &str) -> App<SetupHost> {
    let (pems, root) = pki(10);
    let mut app = app_with(pems);
    put(&app, ROOT, &root.cert_pem);
    put(&app, "/media/usb/openvibes-root.key", &root.key_pem);
    app.install.home = Some(app.root.join("media/usb").display().to_string());
    match answer {
        Some(answer) => app.host.answers.borrow_mut().push_back(answer),
        // A helper still running: the worker never answers.
        None => {
            app.worker = Some(Box::new(|_, _, _| {
                let (tx, rx) = std::sync::mpsc::channel();
                std::mem::forget(tx);
                rx
            }))
        }
    }
    put(&app, PROGRESS, progress);
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Enter);
    for key in [Key::Enter, Key::Down, Key::Enter, Key::Enter, Key::Enter] {
        app.key(key);
    }
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    app
}

#[test]
fn replace_shows_the_step_running_and_where_it_failed() {
    // certs4a.py #8: two stages done, the third running.
    let app = quick_replacing(None, &format!("{}\n{}\n", STEPS[0], STEPS[1]));
    let text = screen(&app);
    for want in [
        "    ✓ Making the new intermediate",
        "    ✓ Trusting the old and the new one",
        " Issuing the server certificates  ingest, distribution, console",
        "    · Restarting the services",
        "Step 3 of 4: Issuing the server certificates",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
    // Failed after the swap: ✓ ✓ ✗ ·, and the helper's sentence.
    let why = "openvibes-admin helper: The intermediate was replaced, but the server \
               certificates were not reissued: run Repair in Maintenance.";
    let failed = Err(HostError::Failed(why.into()));
    let app = quick_replacing(Some(failed), &format!("{}\n{}\n", STEPS[0], STEPS[1]));
    let text = screen(&app);
    for want in [
        "    ✓ Making the new intermediate",
        "    ✓ Trusting the old and the new one",
        "    ✗ Issuing the server certificates",
        "    · Restarting the services",
        "    ✗ The intermediate was replaced, but the server certificates were not",
        "Enter  Back",
    ] {
        assert!(text.contains(want), "missing {want:?} in\n{text}");
    }
}

macro_rules! fixture {
    ($name:literal) => {
        include_str!(concat!("../../../../platform-pki/tests/fixtures/", $name))
    };
}
const FIXTURE_ROOT: &str = fixture!("root.crt");
const ISSUING: &str = fixture!("issuing.crt");

/// Your own CA's page on a host whose intermediate came through the
/// fixtures' issuing CA (its `chain.crt`), the request made; the next
/// one signed by issuing too.
fn own_ca_chain() -> (App<SetupHost>, String) {
    let (csr, _key) = intermediate_request().unwrap();
    let by = platform_pki::KeyAndCert {
        cert_pem: ISSUING.into(),
        key_pem: fixture!("issuing.key").into(),
    };
    let cert = sign_intermediate(&by, &csr, Utc::now()).unwrap();
    let (pems, _) = pki(10);
    let mut app = app_with(pems);
    app.host.plan = plan_text().replace("quick", "careful");
    put(&app, ROOT, FIXTURE_ROOT);
    put(&app, "/etc/openvibes/pki/chain.crt", ISSUING);
    app.host.answers.borrow_mut().extend([
        Ok(format!("request\n{csr}")),
        Ok(format!("signed\tLime Lab Issuing CA\n{csr}")),
    ]);
    app.open_page(Page::Certificates);
    app.key(Key::Down);
    app.key(Key::Enter);
    type_text(&mut app, "pw");
    app.key(Key::Enter);
    (app, cert)
}

/// From the Replace page: the signed certificate pasted and sent.
fn add_signed(app: &mut App<SetupHost>, cert: &str) {
    app.nav.row = 1;
    app.key(Key::Enter);
    app.key(Key::Enter);
    app.key(Key::Paste(cert.to_owned()));
    app.key(Key::Enter);
    type_text(app, "pw");
    app.key(Key::Enter);
}

#[test]
fn replace_own_ca_sends_the_kept_root_then_its_chain() {
    let (mut app, cert) = own_ca_chain();
    let text = screen(&app);
    assert!(text.contains("✓ Lime Lab Root CA (kept)"), "{text}");
    add_signed(&mut app, &cert);
    assert_eq!(
        calls(&app)[1],
        format!(
            "ca-accept --cert {} --root-cert {}\n{}",
            cert.trim(),
            FIXTURE_ROOT.trim(),
            ISSUING.trim()
        )
    );
}

#[test]
fn replace_own_ca_may_add_the_cas_again() {
    let (mut app, cert) = own_ca_chain();
    app.nav.row = 2;
    assert!(screen(&app).contains("Enter  Add your CA's certificate"));
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Install(Stage::Add(Which::Root)));
    app.key(Key::Esc);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    assert!(screen(&app).contains("not added yet"), "{}", screen(&app));
    app.key(Key::Enter);
    app.key(Key::Enter);
    app.key(Key::Paste(format!("{ISSUING}{FIXTURE_ROOT}")));
    app.key(Key::Enter);
    assert_eq!(app.nav.screen, Screen::Maint(Page::Replace));
    assert!(
        screen(&app).contains("✓ added · Lime Lab Root CA"),
        "{}",
        screen(&app)
    );
    add_signed(&mut app, &cert);
    assert_eq!(
        calls(&app)[1],
        format!(
            "ca-accept --cert {} --root-cert {ISSUING}{}",
            cert.trim(),
            FIXTURE_ROOT.trim()
        )
    );
}
