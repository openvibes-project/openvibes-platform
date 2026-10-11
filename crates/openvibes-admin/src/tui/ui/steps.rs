//! A run's steps (spec §2 "Work in progress"): ✓ done, the spinner on the
//! one running, ✗ on the one that failed, – skipped (with why), · to come.
//! More steps than room: the leading done ones fold into one line, and
//! the rest is cut with "· N more steps".

use platform_host::StepState;
use ratatui::text::{Line, Span};

use super::{bar::SPINNER, theme::Theme};

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

#[allow(dead_code, reason = "first used in Task 6 of the 2a plan")]
pub fn lines(
    theme: &Theme,
    titles: &[String],
    states: &[Option<StepState>],
    running: Option<usize>,
    tick: usize,
    room: usize,
) -> Vec<Line<'static>> {
    let state = |i: usize| states.get(i).cloned().flatten();
    let row = |i: usize| -> Line<'static> {
        let title = titles[i].clone();
        if running == Some(i) {
            return Line::from(vec![
                Span::raw("    "),
                Span::styled(SPINNER[tick % SPINNER.len()], theme.teal()),
                Span::raw(" "),
                Span::styled(title, theme.bold()),
            ]);
        }
        match state(i) {
            Some(StepState::Skipped(why)) => {
                Line::styled(format!("    – {title}  {why}"), theme.dim())
            }
            Some(s) if s.finished() => Line::from(vec![
                Span::raw("    "),
                Span::styled("✓", theme.green()),
                Span::raw(format!(" {title}")),
            ]),
            Some(_) => Line::from(vec![
                Span::raw("    "),
                Span::styled("✗", theme.red()),
                Span::raw(" "),
                Span::styled(title, theme.bold()),
            ]),
            None => Line::styled(format!("    · {title}"), theme.dim()),
        }
    };
    let n = titles.len();
    if n <= room {
        return (0..n).map(row).collect();
    }
    let done = (0..n)
        .take_while(|&i| running != Some(i) && state(i).is_some_and(|s| s.finished()))
        .count();
    let mut out = Vec::new();
    if done > 0 {
        out.push(Line::from(vec![
            Span::raw("    "),
            Span::styled("✓", theme.green()),
            Span::raw(format!(" {} done", plural(done, "step", "steps"))),
        ]));
    }
    let left = room.saturating_sub(out.len());
    if n - done <= left {
        out.extend((done..n).map(row));
    } else {
        let shown = left.saturating_sub(1);
        out.extend((done..done + shown).map(row));
        out.push(Line::styled(
            format!("    · {} more steps", n - done - shown),
            theme.dim(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use platform_host::StepState;

    use super::lines;
    use crate::tui::ui::{logo::text, theme::Theme};

    fn titles(names: &[&str]) -> Vec<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    #[test]
    fn every_step_shows_its_state() {
        let t = Theme::new(None, Some("xterm"));
        let names = titles(&[
            "Back up",
            "Stop services",
            "Install packages",
            "Update the database",
        ]);
        let states = vec![
            Some(StepState::Skipped("not chosen".into())),
            Some(StepState::Done("ok".into())),
            None,
            None,
        ];
        assert_eq!(
            text(&lines(&t, &names, &states, Some(2), 0, 10)),
            [
                "    – Back up  not chosen",
                "    ✓ Stop services",
                "    ⠋ Install packages",
                "    · Update the database",
            ]
        );
        let failed = vec![
            Some(StepState::Done("ok".into())),
            Some(StepState::Done("ok".into())),
            Some(StepState::Failed("timed out".into())),
            None,
        ];
        assert_eq!(
            text(&lines(&t, &names, &failed, None, 0, 10))[2],
            "    ✗ Install packages"
        );
    }

    #[test]
    fn too_many_steps_fold_the_done_ones_and_count_the_rest() {
        let t = Theme::new(None, Some("xterm"));
        let names: Vec<String> = (1..=14).map(|n| format!("Step {n}")).collect();
        let mut states = vec![None; 14];
        for state in states.iter_mut().take(5) {
            *state = Some(StepState::Done("ok".into()));
        }
        let out = text(&lines(&t, &names, &states, Some(5), 0, 6));
        assert_eq!(out.len(), 6);
        assert_eq!(out[0], "    ✓ 5 steps done");
        assert_eq!(out[1], "    ⠋ Step 6");
        assert_eq!(out[4], "    · Step 9");
        assert_eq!(out[5], "    · 5 more steps");
    }
}
