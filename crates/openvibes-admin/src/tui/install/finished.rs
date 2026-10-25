//! The Finished screen: what to keep, labelled (install.py, full_advanced.py).
//! Values come from the step details the helper sends (`setup/console.rs`,
//! `setup/pki.rs`); a detail in another wording is shown as it is.

use platform_host::{Host, Step, StepState};
use ratatui::{
    Frame,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use crate::tui::{
    app::App,
    run::Run,
    ui::{bar::Bar, frame, list::Row, logo::Header},
};

/// The step's detail when it finished done.
pub(crate) fn done(states: &[Option<StepState>], step: Step) -> Option<&str> {
    let index = Step::ALL.iter().position(|s| *s == step)?;
    match states.get(index)? {
        Some(StepState::Done(detail)) => Some(detail),
        _ => None,
    }
}

/// The admin password a console detail carries (only when Setup generated
/// one: `setup/console.rs`).
pub(crate) fn admin_password(detail: &str) -> Option<&str> {
    between(detail, ", password ", " (")
}

/// `text` between `start` and `end` (to its end when `end` is absent).
pub(crate) fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let rest = &text[text.find(start)? + start.len()..];
    Some(rest.find(end).map_or(rest, |at| &rest[..at]))
}

fn row(name: &str, value: Vec<Span<'static>>) -> Row {
    Row::Entry {
        name: vec![Span::raw(name.to_owned())],
        value,
    }
}

fn bold(text: &str) -> Span<'static> {
    Span::styled(text.to_owned(), Style::new().add_modifier(Modifier::BOLD))
}

fn dim(text: &str) -> Span<'static> {
    Span::styled(text.to_owned(), Style::new().add_modifier(Modifier::DIM))
}

/// The rows to keep, from the steps' states (indexed as `Step::ALL`);
/// `signed` is who signed the intermediate of "Your own CA".
pub fn finished_rows(states: &[Option<StepState>], signed: Option<&str>) -> Vec<Row> {
    let console = done(states, Step::Console);
    let url = console.and_then(|d| d.split(" · ").next().filter(|u| u.starts_with("https://")));
    let mut rows = Vec::new();
    if let Some(url) = url {
        rows.push(row("Open the console", vec![bold(url)]));
    }
    rows.push(row("Sign in as", vec![bold("admin")]));
    if let Some(password) = console.and_then(admin_password) {
        rows.push(row(
            "Password",
            vec![
                bold(password),
                Span::raw("   "),
                Span::styled(
                    "shown only now: write it down",
                    Style::new().fg(ratatui::style::Color::Yellow),
                ),
            ],
        ));
    }
    let ca = done(states, Step::Ca);
    if let Some(path) = ca.and_then(|d| between(d, "root key saved to ", ": keep it offline")) {
        rows.push(row("Root key", vec![bold(path)]));
        rows.push(row(
            "",
            vec![dim("move it to a USB stick and keep it offline")],
        ));
    } else if let Some(ca) = ca {
        let (what, sha) = match ca.split_once(", SHA-256 ") {
            Some((what, sha)) => (what, Some(sha)),
            None => (ca, None),
        };
        let who = signed.map_or_else(|| what.to_owned(), |who| format!("signed by {who}"));
        rows.push(row("Certificates", vec![bold(&who)]));
        // Compared by hand, so shown whole: 16 bytes a line.
        let bytes: Vec<&str> = sha.map_or_else(Vec::new, |sha| sha.split(':').collect());
        for (i, half) in bytes.chunks(16).enumerate() {
            let name = if i == 0 { "Root CA SHA-256" } else { "" };
            rows.push(row(name, vec![bold(&half.join(":"))]));
        }
        rows.push(row(
            "",
            vec![dim("browsers that trust your CA show no warning")],
        ));
    }
    rows
}

/// The rows as lines: the name in a 20-wide column, then its value.
fn lines(rows: Vec<Row>) -> Vec<Line<'static>> {
    rows.into_iter()
        .filter_map(|row| match row {
            Row::Entry { name, value } => {
                let text: String = name.iter().map(|s| s.content.as_ref()).collect();
                let mut spans = vec![Span::raw(format!("    {text:<20}"))];
                spans.extend(value);
                Some(Line::from(spans))
            }
            Row::Heading { .. } => None,
        })
        .collect()
}

/// The states of a run, indexed as `Step::ALL`: a step the run did not
/// include is `None`.
pub(super) fn step_states(run: &Run) -> Vec<Option<StepState>> {
    use crate::tui::run::Call;
    Step::ALL
        .iter()
        .map(|step| {
            let at = run
                .work
                .calls
                .iter()
                .position(|c| *c == Call::Setup(*step))?;
            run.states[at].clone()
        })
        .collect()
}

pub(super) fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>, run: &Run) {
    let t = &app.theme;
    let area = frame::draw(
        frame,
        t,
        head,
        Some("OpenVIBES is installed"),
        &app.bar(Bar::only(&[("Enter", "Continue to Home")])),
    );
    let states = step_states(run);
    let mut out = vec![Line::raw("")];
    // "signed by X" only for your own CA.
    let signed = app
        .install
        .signed
        .as_deref()
        .filter(|_| app.install.ca == super::Ca::Own);
    out.extend(lines(finished_rows(&states, signed)));
    out.push(Line::raw(""));
    out.push(Line::styled(
        if done(&states, Step::Console)
            .and_then(admin_password)
            .is_some()
        {
            "    Next: sign in, change the password, then add hosts under Enrollment."
        } else {
            "    Next: sign in, then add hosts under Enrollment."
        },
        t.dim(),
    ));
    frame.render_widget(Paragraph::new(out), area);
}
