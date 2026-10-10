//! The bottom bar (spec §2): a dim box, one line inside. Keys are buttons;
//! ⭡⭣ Move comes first unless a question is asked or a value typed; Esc
//! Back and ? sit at the right (q Quit and ? on Home). Questions, typing
//! and running work take the bar's place.

use ratatui::text::{Line, Span};

use super::theme::Theme;

pub const HEIGHT: u16 = 3;
const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Bar {
    Keys {
        keys: Vec<(String, String)>,
        nav: bool,
        home: bool,
    },
    Ask {
        question: String,
        detail: String,
        yes: bool,
    },
    /// A value being typed: what it is, how it shows (masked for a
    /// password), what Enter does.
    Typing {
        label: String,
        shown: String,
        done: String,
    },
    Busy {
        text: String,
        tick: usize,
    },
    Done {
        ok: bool,
        text: String,
    },
}

impl Bar {
    pub fn keys(keys: &[(&str, &str)]) -> Bar {
        Bar::Keys {
            keys: owned(keys),
            nav: true,
            home: false,
        }
    }
    pub fn home(keys: &[(&str, &str)]) -> Bar {
        Bar::Keys {
            keys: owned(keys),
            nav: true,
            home: true,
        }
    }

    pub fn lines(&self, theme: &Theme, width: u16) -> [Line<'static>; 3] {
        // " │ " + content + " │" fills the box, which is `width - 1` wide.
        let inner = usize::from(width.saturating_sub(6));
        let (mut left, mut right) = self.parts(theme);
        let len = |spans: &[Span]| {
            spans
                .iter()
                .map(|s| s.content.chars().count())
                .sum::<usize>()
        };
        // A question keeps its buttons: its detail (the last span) gives way.
        if matches!(self, Bar::Ask { .. }) && len(&left) + len(&right) + 1 > inner {
            let over = len(&left) + len(&right) + 2 - inner;
            if let Some(detail) = left.last_mut() {
                let keep = detail.content.chars().count().saturating_sub(over);
                let cut: String = detail.content.chars().take(keep).collect();
                detail.content = format!("{cut}…").into();
            }
        }
        // Too long: drop the right group, then cut the left with "…".
        if len(&left) + len(&right) + 1 > inner {
            right.clear();
        }
        if len(&left) + 1 > inner {
            let mut room = inner.saturating_sub(2);
            for span in &mut left {
                let n = span.content.chars().count().min(room);
                span.content = span.content.chars().take(n).collect::<String>().into();
                room -= n;
            }
            left.push(Span::raw("…"));
        }
        let used = len(&left) + len(&right);
        let mut spans = vec![
            Span::raw(" "),
            Span::styled("│", theme.dim()),
            Span::raw(" "),
        ];
        spans.extend(left);
        spans.push(Span::raw(" ".repeat(inner.saturating_sub(used).max(1))));
        spans.extend(right);
        spans.push(Span::raw(" "));
        spans.push(Span::styled("│", theme.dim()));
        let rule = "─".repeat(usize::from(width.saturating_sub(4)));
        [
            Line::from(vec![
                Span::raw(" "),
                Span::styled(format!("┌{rule}┐"), theme.dim()),
            ]),
            Line::from(spans),
            Line::from(vec![
                Span::raw(" "),
                Span::styled(format!("└{rule}┘"), theme.dim()),
            ]),
        ]
    }

    fn parts(&self, theme: &Theme) -> (Vec<Span<'static>>, Vec<Span<'static>>) {
        // A key button, its label, then the gap to the next group (its
        // own leading space makes it three).
        let key = |k: &str, label: &str| {
            vec![
                Span::styled(format!(" {k} "), theme.key()),
                Span::raw(format!(" {label}  ")),
            ]
        };
        match self {
            Bar::Keys { keys, nav, home } => {
                let mut left = Vec::new();
                if *nav {
                    left.extend(key(theme.up_down(), "Move"));
                }
                for (k, label) in keys {
                    left.extend(key(k, label));
                }
                let mut right = if *home {
                    key("q", "Quit")
                } else {
                    key("Esc", "Back")
                };
                right.extend([Span::raw(" "), Span::styled(" ? ", theme.key())]);
                (left, right)
            }
            Bar::Ask {
                question,
                detail,
                yes,
            } => {
                let left = vec![
                    Span::styled(question.clone(), theme.bold()),
                    Span::raw(" "),
                    Span::styled(detail.clone(), theme.dim()),
                ];
                let (y, n) = if *yes {
                    (theme.highlight(), theme.dim())
                } else {
                    (theme.dim(), theme.highlight())
                };
                let right = vec![
                    Span::styled(if *yes { " Yes " } else { "[ Yes ]" }, y),
                    Span::raw(" "),
                    Span::styled(if *yes { "[ No ]" } else { " No " }, n),
                    Span::raw("  "),
                    Span::styled(format!(" {} ", theme.left_right()), theme.key()),
                    Span::raw(" "),
                    Span::styled(" Enter ", theme.key()),
                    Span::raw(" Confirm"),
                ];
                (left, right)
            }
            Bar::Typing { label, shown, done } => {
                let mut left = vec![
                    Span::styled(format!("{label}: "), theme.bold()),
                    Span::raw(format!("{shown}█  ")),
                ];
                left.extend(key("Enter", done));
                let right = vec![Span::styled(" Esc ", theme.key()), Span::raw(" Cancel")];
                (left, right)
            }
            Bar::Busy { text, tick } => (
                vec![
                    Span::styled(SPINNER[tick % SPINNER.len()], theme.teal()),
                    Span::raw(format!(" {text}")),
                ],
                Vec::new(),
            ),
            Bar::Done { ok, text } => (
                vec![
                    if *ok {
                        Span::styled("✓", theme.green())
                    } else {
                        Span::styled("✗", theme.red())
                    },
                    Span::raw(format!(" {text}")),
                ],
                Vec::new(),
            ),
        }
    }
}

fn owned(keys: &[(&str, &str)]) -> Vec<(String, String)> {
    keys.iter()
        .map(|(k, l)| ((*k).to_owned(), (*l).to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::ui::logo::text;

    fn plain() -> Theme {
        Theme::new(None, Some("xterm"))
    }

    #[test]
    fn keys_start_with_move_and_end_with_back_and_help() {
        let bar = Bar::keys(&[("Enter", "Restart ingest")]);
        let t = text(&bar.lines(&plain(), 80));
        assert_eq!(t[0], format!(" ┌{}┐", "─".repeat(76)));
        assert!(
            t[1].starts_with(" │  ⭡⭣  Move   Enter  Restart ingest"),
            "{:?}",
            t[1]
        );
        assert!(t[1].ends_with("  Esc  Back    ?  │"), "{:?}", t[1]);
        assert_eq!(t[1].chars().count(), 79);
    }

    #[test]
    fn a_long_question_shortens_its_detail_and_keeps_the_buttons() {
        let bar = Bar::Ask {
            question: "Restart ingest?".into(),
            detail: "agents reconnect within a minute and keep going".into(),
            yes: true,
        };
        let t = text(&bar.lines(&plain(), 80));
        assert!(
            t[1].contains("…") && t[1].contains("Enter  Confirm"),
            "{:?}",
            t[1]
        );
        assert_eq!(t[1].chars().count(), 79);
    }

    #[test]
    fn home_offers_quit_instead_of_back() {
        let t = text(&Bar::home(&[("Enter", "Open")]).lines(&plain(), 80));
        assert!(
            t[1].ends_with("  q  Quit    ?  │") && !t[1].contains("Back"),
            "{:?}",
            t[1]
        );
    }

    #[test]
    fn a_question_has_buttons_arrows_and_enter_confirm_and_no_move() {
        let bar = Bar::Ask {
            question: "Restart ingest?".into(),
            detail: "agents reconnect".into(),
            yes: true,
        };
        let t = text(&bar.lines(&plain(), 80));
        assert!(
            t[1].starts_with(" │ Restart ingest? agents reconnect"),
            "{:?}",
            t[1]
        );
        assert!(
            t[1].contains(" Yes  [ No ]   ⭠⭢   Enter  Confirm"),
            "{:?}",
            t[1]
        );
        assert!(!t[1].contains("Move"));
    }

    #[test]
    fn busy_and_done_say_what_happens() {
        let t = text(
            &Bar::Busy {
                text: "Restarting ingest…".into(),
                tick: 0,
            }
            .lines(&plain(), 80),
        );
        assert!(t[1].starts_with(" │ ⠋ Restarting ingest…"), "{:?}", t[1]);
        let t = text(
            &Bar::Done {
                ok: true,
                text: "ingest restarted and ready (4 s)".into(),
            }
            .lines(&plain(), 80),
        );
        assert!(
            t[1].starts_with(" │ ✓ ingest restarted and ready (4 s)"),
            "{:?}",
            t[1]
        );
        let t = text(
            &Bar::Done {
                ok: false,
                text: "ingest did not start".into(),
            }
            .lines(&plain(), 80),
        );
        assert!(t[1].starts_with(" │ ✗ ingest did not start"));
    }

    #[test]
    fn plain_arrows_on_the_linux_console() {
        let t = text(&Bar::keys(&[]).lines(&Theme::new(None, Some("linux")), 80));
        assert!(t[1].contains(" ↑↓  Move"), "{:?}", t[1]);
    }

    #[test]
    fn an_overlong_question_stays_inside_the_box() {
        let bar = Bar::Ask {
            question: "Really do this very long thing?".repeat(4),
            detail: "x".into(),
            yes: true,
        };
        let t = text(&bar.lines(&plain(), 80));
        assert_eq!(t[1].chars().count(), 79, "{:?}", t[1]);
        assert!(t[1].ends_with('│') && t[1].contains('…'), "{:?}", t[1]);
    }
}
