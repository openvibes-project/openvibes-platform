//! The console sign-in (#565) against the approved mockup (signin.py).

use ratatui::{Terminal, backend::TestBackend};

use super::{SignIn, draw, reach};
use crate::tui::{app::Key, ui::theme::Theme};

fn screen(sign_in: &SignIn) -> String {
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    let theme = Theme::new(None, Some("xterm-256color"));
    terminal
        .draw(|frame| draw(frame, &theme, "openvibes-va", sign_in))
        .unwrap();
    let buffer = terminal.backend().buffer();
    (0..buffer.area.height)
        .map(|y| {
            let line: String = (0..buffer.area.width)
                .map(|x| buffer[(x, y)].symbol())
                .collect();
            line.trim_end().to_owned() + "\n"
        })
        .collect()
}

fn typed(sign_in: &mut SignIn, text: &str) {
    for c in text.chars() {
        sign_in.key(Key::Char(c));
    }
}

#[test]
fn the_screen_is_the_mockups() {
    let mut sign_in = SignIn {
        reach: reach(
            Some("https://openvibes-va.lime.lab".into()),
            Some("lime@192.168.1.50".into()),
        ),
        ..SignIn::default()
    };
    let text = screen(&sign_in);
    for line in [
        "openvibes-va · Sign in",
        "━━ Sign in to this appliance ━━",
        "▸ Account            █",
        "Password",
        "Sign in            opens the menu",
        "The account made when the appliance was installed, or another one.",
        "The console: https://openvibes-va.lime.lab · SSH: lime@192.168.1.50",
        "Enter  Next",
    ] {
        assert!(text.contains(line), "{line}\n{text}");
    }
    // An empty line between the header and Account (lime, 2026-11-27).
    let lines: Vec<&str> = text.lines().collect();
    let head = lines.iter().position(|l| l.contains("━━ Sign in")).unwrap();
    assert_eq!(lines[head + 1], "", "{text}");

    typed(&mut sign_in, "lime");
    assert!(!sign_in.key(Key::Enter));
    typed(&mut sign_in, "secret");
    let text = screen(&sign_in);
    assert!(text.contains("Account            lime\n"), "{text}");
    assert!(text.contains("▸ Password           ••••••█"), "{text}");
    assert!(!text.contains("secret"), "{text}");
    assert!(text.contains("Three wrong ones lock the account"), "{text}");
    assert!(
        !sign_in.key(Key::Enter),
        "Enter on Password goes to Sign in"
    );
    assert!(screen(&sign_in).contains("Enter  Sign in"));
    assert!(sign_in.key(Key::Enter), "Enter on Sign in checks");
}

#[test]
fn wrong_passwords_count_down_to_the_lock() {
    let mut sign_in = SignIn::default();
    typed(&mut sign_in, "lime");
    sign_in.key(Key::Enter);
    typed(&mut sign_in, "wrong");
    sign_in.refused();
    assert!(sign_in.password.is_empty());
    assert_eq!(sign_in.row, 1);
    assert_eq!(sign_in.account, "lime", "the account is kept");
    assert!(
        screen(&sign_in)
            .contains("✗ Wrong account or password. 2 tries left before a 10-minute lock."),
        "{}",
        screen(&sign_in)
    );
    sign_in.refused();
    assert!(sign_in.error.as_deref().unwrap().contains("1 try left"));
    sign_in.refused();
    assert!(
        sign_in
            .error
            .as_deref()
            .unwrap()
            .contains("locked for 10 minutes")
    );
    // Another account starts its own count.
    sign_in.account = "ann".into();
    sign_in.refused();
    assert!(sign_in.error.as_deref().unwrap().contains("2 tries left"));
}

#[test]
fn an_empty_account_does_not_check_and_reach_skips_the_unknown() {
    let mut sign_in = SignIn {
        row: 2,
        ..SignIn::default()
    };
    assert!(!sign_in.key(Key::Enter));
    assert_eq!(
        reach(None, Some("192.168.1.50".into())),
        "SSH: 192.168.1.50"
    );
    assert_eq!(reach(None, None), "");
}
