//! Maintenance › Database (spec §6, maint3.py): a report only. Migrations
//! run in Update, and the clean-up runs by itself every night (the
//! maintenance timer), so neither has a button (spec §1.5).

use chrono::NaiveDate;
use platform_host::{Database, Host, StepState, Unit};
use platform_store::SCHEMA_VERSION;
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
const KEPT: &str = "90 days (set in the console)";

pub fn work() -> Work {
    Work::new(
        Kind::Report,
        vec![
            Call::Database(Database::Status),
            Call::Disk,
            Call::Logs(Unit::Maintenance, 50),
        ],
    )
}

fn field<'a>(text: &'a str, name: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|l| l.strip_prefix(name))
        .map(str::trim)
}

/// The last clean-up in its journal: its date, and what it removed.
pub fn last_cleanup(journal: &str) -> Option<(String, String)> {
    let line = journal
        .lines()
        .rev()
        .find(|l| l.contains("partitions, dropped "))?;
    let stamp = line.split_whitespace().next()?;
    let date = stamp.get(..10)?.to_owned();
    let number = |after: &str| {
        let rest = line.split(after).nth(1)?;
        let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
        (!digits.is_empty()).then_some(digits)
    };
    let days = number("dropped ")?;
    let audit = number("deleted ").unwrap_or_else(|| "0".into());
    let unit = if days == "1" { "day" } else { "days" };
    Some((
        date,
        format!("{days} {unit} of findings, {audit} audit events"),
    ))
}

/// "100G" as "100 GB".
fn unit(size: &str) -> String {
    match size.char_indices().last() {
        Some((i, c)) if c.is_ascii_alphabetic() => format!("{} {c}B", &size[..i]),
        _ => size.to_owned(),
    }
}

/// The page's rows. `disk` is the `Call::Disk` text; `today` dates the
/// clean-up. The timer's time of day is not shown: no Host call reads it.
pub fn rows(
    status: Result<&str, &str>,
    journal: Option<&str>,
    disk: Option<&str>,
    today: NaiveDate,
) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    match status {
        Ok(text) => {
            let schema = match field(text, "schema version") {
                Some(v) if v == SCHEMA_VERSION.to_string() => format!("{v} · up to date"),
                Some(v) => format!("{v} · migration pending"),
                None => "unknown".to_owned(),
            };
            rows.push(("Schema".into(), schema));
            let mut size = field(text, "database size")
                .and_then(|s| s.trim_end_matches("MiB").trim().parse::<u64>().ok())
                .map_or("unknown".to_owned(), |mib| human(mib * 1024 * 1024));
            let mut parts = disk.unwrap_or("").split('\t');
            if let (Some(total), Some(used)) = (parts.next(), parts.next())
                && !total.is_empty()
            {
                size.push_str(&format!(" on a {} disk ({used}% used)", unit(total)));
            }
            rows.push(("Size".into(), size));
        }
        Err(error) if error.contains("not current") => {
            rows.push(("Schema".into(), "migration pending".to_owned()))
        }
        Err(error) => rows.push(("Database".into(), error.to_owned())),
    }
    rows.push(("Data kept".into(), KEPT.to_owned()));
    match journal.and_then(last_cleanup) {
        Some((date, removed)) => {
            let day = |d: Option<NaiveDate>| d.map(|d| d.to_string());
            let recent = date == today.to_string() || Some(&date) == day(today.pred_opt()).as_ref();
            let ran = if date == today.to_string() {
                "today"
            } else {
                &date
            };
            rows.push(("Clean-up".into(), format!("automatic, nightly · ran {ran}")));
            let label = if recent {
                "Removed last night".to_owned()
            } else {
                format!("Removed {date}")
            };
            rows.push((label, removed));
        }
        None => rows.push((
            "Clean-up".into(),
            "automatic, nightly · not run yet".to_owned(),
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
            let done = |i: usize| match run.states.get(i) {
                Some(Some(StepState::Done(text))) => Some(text.as_str()),
                _ => None,
            };
            let today = chrono::Local::now().date_naive();
            for (name, value) in rows(status, done(2), done(1), today) {
                let spans = match value.strip_prefix("automatic") {
                    Some(rest) => vec![
                        Span::styled("automatic", t.green()),
                        Span::raw(rest.to_owned()),
                    ],
                    None if name == "Database" => vec![Span::styled(value, t.red())],
                    None => vec![Span::raw(value)],
                };
                lines.push(info(&name, spans));
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
    use chrono::NaiveDate;
    use platform_host::Database;
    use platform_store::SCHEMA_VERSION;

    use super::{last_cleanup, rows};
    use crate::tui::{
        app::Key,
        maint::{Page, human, row_of},
        nav::Screen,
        tests::{app, screen},
    };

    fn row(name: &str, value: String) -> (String, String) {
        (name.to_owned(), value)
    }
    const DISK: &str = "100G\t41\t70G";
    fn day(d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 10, d).unwrap()
    }

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
            &format!("{SCHEMA_VERSION} · up to date"),
            "42 MB on a 100 GB disk (40% used)",
            "90 days (set in the console)",
            "automatic, nightly · not run yet",
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
    fn opening_the_page_reads_the_disk_on_the_worker_not_the_ui_thread() {
        let mut app = app(false);
        app.host.disk_calls.set(0);
        app.worker = Some(Box::new(|_, _, _| std::sync::mpsc::channel().1));
        app.key(Key::Down);
        app.key(Key::Enter);
        app.nav.row = row_of("Database");
        app.key(Key::Enter);
        assert_eq!(app.host.disk_calls.get(), 0);
        assert!(
            app.load
                .as_ref()
                .unwrap()
                .work
                .calls
                .contains(&crate::tui::run::Call::Disk)
        );
    }

    #[test]
    fn the_last_clean_up_is_read_from_its_journal() {
        let journal = "2026-10-11T00:41:02+02:00 limebox openvibes-admin[4242]: created 1 partitions, dropped 1, deleted 12 expired audit events\n\
                       2026-10-11T00:41:02+02:00 limebox openvibes-admin[4242]: recorded history for 8 hosts, deleted 0 old rows";
        assert_eq!(
            last_cleanup(journal),
            Some((
                "2026-10-11".to_owned(),
                "1 day of findings, 12 audit events".to_owned()
            ))
        );
        assert_eq!(last_cleanup("Started openvibes-maintenance.timer"), None);
    }

    #[test]
    fn the_rows_use_the_mockups_wording() {
        let ok = format!("schema version {SCHEMA_VERSION}\ndatabase size 3174 MiB\n");
        let journal = "2026-10-10T00:41:02+02:00 h a[1]: created 1 partitions, dropped 2, deleted 0 expired audit events";
        let r = rows(Ok(&ok), Some(journal), Some(DISK), day(11));
        assert_eq!(
            r[0],
            row("Schema", format!("{SCHEMA_VERSION} · up to date"))
        );
        assert_eq!(
            r[1],
            row("Size", "3.1 GB on a 100 GB disk (41% used)".to_owned())
        );
        assert_eq!(
            r[2],
            row("Data kept", "90 days (set in the console)".to_owned())
        );
        assert_eq!(
            r[3],
            row("Clean-up", "automatic, nightly · ran 2026-10-10".to_owned())
        );
        assert_eq!(
            r[4],
            row(
                "Removed last night",
                "2 days of findings, 0 audit events".to_owned()
            )
        );
        let today = "2026-10-11T00:41:02+02:00 h a[1]: created 1 partitions, dropped 1, deleted 0 expired audit events";
        let r = rows(Ok(&ok), Some(today), None, day(11));
        assert_eq!(r[1].1, "3.1 GB");
        assert_eq!(r[3].1, "automatic, nightly · ran today");
        let r = rows(Ok(&ok), Some(journal), None, day(14));
        assert_eq!(r[4].0, "Removed 2026-10-10");
    }

    #[test]
    fn a_pending_or_unreachable_database_says_so_and_sizes_read_well() {
        let r = rows(Err("failed: database unavailable"), None, None, day(11));
        assert_eq!(
            r[0],
            row("Database", "failed: database unavailable".to_owned())
        );
        let r = rows(
            Err("failed: schema is not current; run openvibes-admin migrate"),
            None,
            None,
            day(11),
        );
        assert_eq!(r[0], row("Schema", "migration pending".to_owned()));
        let old = rows(
            Ok("schema version 3\ndatabase size 1 MiB\n"),
            None,
            None,
            day(11),
        );
        assert_eq!(old[0], row("Schema", "3 · migration pending".to_owned()));
        assert_eq!(human(42 * 1024 * 1024), "42 MB");
        assert_eq!(human(431), "1 KB");
    }
}
