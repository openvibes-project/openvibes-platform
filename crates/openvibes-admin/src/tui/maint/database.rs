//! Maintenance › Database (spec §6, maint3.py): a report only. Migrations
//! run in Update, and the clean-up runs by itself every night (the
//! maintenance timer), so neither has a button (spec §1.5).

use platform_host::{Database, DiskUse, Host, StepState, Unit};
use ratatui::{
    Frame,
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{human, info};
use crate::tui::{
    app::App,
    run::{Call, Kind, Work},
    ui::{
        bar::{Bar, SPINNER},
        frame,
        logo::Header,
    },
};

/// What the nightly clean-up keeps: `maintenance`'s default, which the
/// timer runs with.
const KEPT: &str = "90 days of findings";

pub fn work() -> Work {
    Work::new(
        Kind::Report,
        vec![
            Call::Database(Database::Status),
            Call::Logs(Unit::Maintenance, 50),
        ],
    )
}

fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.strip_prefix(name))
        .map(str::trim)
}

/// The last clean-up in its journal: when, and what it removed.
pub fn last_cleanup(journal: &str) -> Option<(String, String)> {
    let line = journal
        .lines()
        .rev()
        .find(|l| l.contains("partitions, dropped "))?;
    let stamp = line.split_whitespace().next()?.replacen('T', " ", 1);
    let when = stamp.get(..16).unwrap_or(&stamp).to_owned();
    let number = |after: &str| {
        let rest = line.split(after).nth(1)?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty()).then_some(digits)
    };
    let days = number("dropped ")?;
    let audit = number("deleted ").unwrap_or_else(|| "0".into());
    let unit = if days == "1" { "day" } else { "days" };
    Some((
        when,
        format!("{days} {unit} of findings, {audit} audit events"),
    ))
}

pub fn rows(
    status: Result<&str, &str>,
    journal: Option<&str>,
    disk: Option<&DiskUse>,
) -> Vec<(&'static str, String)> {
    let mut rows = Vec::new();
    match status {
        Ok(text) => {
            let schema = field(text, "schema version")
                .map_or("unknown".to_owned(), |v| format!("{v} · up to date"));
            rows.push(("Schema", schema));
            let mut size = field(text, "database size")
                .and_then(|s| s.trim_end_matches("MiB").trim().parse::<u64>().ok())
                .map_or("unknown".to_owned(), |mib| human(mib * 1024 * 1024));
            if let Some(d) = disk {
                size.push_str(&format!(
                    " · disk {}% used, {} free",
                    d.used_percent, d.available
                ));
            }
            rows.push(("Size", size));
        }
        Err(error) => rows.push(("Database", error.to_owned())),
    }
    rows.push(("Data kept", KEPT.to_owned()));
    match journal.and_then(last_cleanup) {
        Some((when, removed)) => {
            rows.push((
                "Clean-up",
                format!("automatic, every night · last run {when}"),
            ));
            rows.push(("Removed last run", removed));
        }
        None => rows.push((
            "Clean-up",
            "automatic, every night · not run yet".to_owned(),
        )),
    }
    rows
}

pub fn draw<H: Host>(frame: &mut Frame, head: &Header, app: &App<H>) {
    let t = &app.theme;
    let area = frame::draw(frame, t, head, Some("Database"), &app.bar(Bar::act(&[])));
    let mut lines = vec![Line::raw("")];
    match app
        .load
        .as_ref()
        .filter(|r| r.work.kind == Kind::Report && !r.running())
    {
        Some(run) => {
            let status = match &run.states[0] {
                Some(StepState::Done(text)) => Ok(text.as_str()),
                Some(other) => Err(other.detail()),
                None => Err("not read"),
            };
            let journal = match run.states.get(1) {
                Some(Some(StepState::Done(text))) => Some(text.as_str()),
                _ => None,
            };
            for (name, value) in rows(status, journal, app.maint.disk.as_ref()) {
                let style = if name == "Database" {
                    t.red()
                } else {
                    ratatui::style::Style::new()
                };
                lines.push(info(name, vec![Span::styled(value, style)]));
            }
        }
        None => lines.push(Line::from(vec![
            Span::raw("    "),
            Span::styled(SPINNER[app.tick_count % SPINNER.len()], t.teal()),
            Span::raw(" Reading the database…"),
        ])),
    }
    frame.render_widget(Paragraph::new(lines), area);
}

#[cfg(test)]
mod tests {
    use platform_host::{Database, DiskUse};

    use super::{last_cleanup, rows};
    use crate::tui::{
        app::Key,
        maint::{Page, human, row_of},
        nav::Screen,
        tests::{app, screen},
    };

    #[test]
    fn the_database_page_is_a_report_with_no_actions() {
        let mut app = app(false);
        app.key(Key::Down);
        app.key(Key::Enter);
        app.nav.row = row_of("Database");
        app.key(Key::Enter);
        assert_eq!(app.nav.screen, Screen::Maint(Page::Database));
        let text = screen(&app, 80, 24);
        for want in [
            "Maintenance › Database",
            "25 · up to date",
            "42 MB · disk 40% used, 20G free",
            "90 days of findings",
            "automatic, every night · not run yet",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
        assert!(
            !text.contains("Move") && !text.contains("igrate"),
            "a report: no actions\n{text}"
        );
        assert_eq!(*app.host.database_calls.borrow(), [Database::Status]);
    }

    #[test]
    fn the_last_clean_up_is_read_from_its_journal() {
        let journal = "2026-10-11T00:41:02+02:00 limebox openvibes-admin[4242]: created 1 partitions, dropped 1, deleted 12 expired audit events\n\
                       2026-10-11T00:41:02+02:00 limebox openvibes-admin[4242]: recorded history for 8 hosts, deleted 0 old rows";
        assert_eq!(
            last_cleanup(journal),
            Some((
                "2026-10-11 00:41".to_owned(),
                "1 day of findings, 12 audit events".to_owned()
            ))
        );
        assert_eq!(last_cleanup("Started openvibes-maintenance.timer"), None);
    }

    #[test]
    fn an_unreachable_database_says_why_and_sizes_read_well() {
        let rows = rows(Err("failed: database unavailable"), None, None);
        assert_eq!(
            rows[0],
            ("Database", "failed: database unavailable".to_owned())
        );
        let disk = DiskUse {
            path: "/var/lib/pgsql".into(),
            used_percent: 41,
            available: "70G".into(),
        };
        let ok = super::rows(
            Ok("schema version 46\ndatabase size 3174 MiB\n"),
            None,
            Some(&disk),
        );
        assert_eq!(
            ok[1],
            ("Size", "3.1 GB · disk 41% used, 70G free".to_owned())
        );
        assert_eq!(human(42 * 1024 * 1024), "42 MB");
        assert_eq!(human(431), "1 KB");
    }
}
