//! The one list every screen uses (spec §2): an empty line between
//! entries, headings directly on their list, a highlighted entry, and
//! scrolling one row per step with "⭡ N more" / "⭣ N more" in the gap
//! lines above the first and below the last visible entry.

use ratatui::text::{Line, Span};

use super::theme::Theme;

#[derive(Clone, Debug)]
pub enum Row {
    Heading { text: String, right: String },
    Entry { name: Vec<Span<'static>>, value: Vec<Span<'static>> },
}

impl Row {
    pub fn entry(name: &str, value: &str) -> Row {
        Row::Entry { name: vec![Span::raw(name.to_owned())], value: vec![Span::raw(value.to_owned())] }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Scroll {
    /// The first laid-out line shown.
    pub top: usize,
}

pub fn entries(rows: &[Row]) -> usize {
    rows.iter().filter(|r| matches!(r, Row::Entry { .. })).count()
}

fn width(spans: &[Span]) -> usize {
    spans.iter().map(|s| s.content.chars().count()).sum()
}

/// Every row laid out: the line, and which entry it is (if one).
fn layout(theme: &Theme, rows: &[Row], selected: usize, name_w: usize) -> Vec<(Line<'static>, Option<usize>)> {
    let mut out = Vec::new();
    let mut entry = 0;
    let mut last_was_entry = false;
    for (i, row) in rows.iter().enumerate() {
        match row {
            Row::Heading { text, right } => {
                if i > 0 {
                    out.push((Line::raw(""), None));
                }
                let gap = 72usize.saturating_sub(4 + text.chars().count() + right.chars().count()).max(1);
                out.push((
                    Line::from(vec![
                        Span::raw("    "),
                        Span::styled(text.clone(), theme.bold()),
                        Span::raw(" ".repeat(gap)),
                        Span::styled(right.clone(), theme.dim()),
                    ]),
                    None,
                ));
                last_was_entry = false;
            }
            Row::Entry { name, value } => {
                if last_was_entry {
                    out.push((Line::raw(""), None));
                }
                let pad = " ".repeat(name_w.saturating_sub(width(name)) + 1);
                let mut spans = Vec::new();
                if entry == selected {
                    let hl = theme.highlight();
                    spans.push(Span::styled("  ▸ ", hl));
                    spans.extend(name.iter().map(|s| Span::styled(s.content.clone(), hl)));
                    spans.push(Span::styled(pad, hl));
                    spans.extend(value.iter().map(|s| Span::styled(s.content.clone(), hl)));
                    let tail = 72usize.saturating_sub(4 + name_w + 1 + width(value));
                    spans.push(Span::styled(" ".repeat(tail), hl));
                } else {
                    spans.push(Span::raw("    "));
                    spans.extend(name.iter().cloned());
                    spans.push(Span::raw(pad));
                    spans.extend(value.iter().map(|s| Span::styled(s.content.clone(), s.style.patch(theme.dim()))));
                }
                out.push((Line::from(spans), Some(entry)));
                entry += 1;
                last_was_entry = true;
            }
        }
    }
    out
}

pub fn lines(
    theme: &Theme,
    rows: &[Row],
    selected: usize,
    scroll: &mut Scroll,
    height: u16,
    name_w: usize,
) -> Vec<Line<'static>> {
    let laid = layout(theme, rows, selected, name_w);
    // Two lines of the height are the hint lines above and below.
    let inner = usize::from(height).saturating_sub(2).max(1);
    let at = laid.iter().position(|(_, e)| *e == Some(selected)).unwrap_or(0);
    if at < scroll.top {
        scroll.top = at;
    } else if at >= scroll.top + inner {
        scroll.top = at + 1 - inner;
    }
    scroll.top = scroll.top.min(laid.len().saturating_sub(inner));
    let window = &laid[scroll.top..(scroll.top + inner).min(laid.len())];
    let above = laid[..scroll.top].iter().filter(|(_, e)| e.is_some()).count();
    let below = laid[(scroll.top + window.len())..].iter().filter(|(_, e)| e.is_some()).count();
    let hint = |n: usize, arrow: &str| {
        if n == 0 {
            Line::raw("")
        } else {
            Line::from(vec![Span::raw("    "), Span::styled(format!("{arrow} {n} more"), theme.dim())])
        }
    };
    let mut out = vec![hint(above, theme.up())];
    out.extend(window.iter().map(|(l, _)| l.clone()));
    out.push(hint(below, theme.down()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::ui::logo::text;

    fn theme() -> Theme {
        Theme::new(None, Some("xterm"))
    }

    fn rows(n: usize) -> Vec<Row> {
        (0..n).map(|i| Row::entry(&format!("item{i}"), &format!("value {i}"))).collect()
    }

    #[test]
    fn one_empty_line_between_entries_and_the_highlight_at_column_two() {
        let mut scroll = Scroll::default();
        let t = text(&lines(&theme(), &rows(3), 1, &mut scroll, 13, 15));
        assert_eq!(t[0], "", "the gap above the first entry");
        assert_eq!(t[1].trim_end(), "    item0           value 0");
        assert_eq!(t[2], "");
        assert!(t[3].starts_with("  ▸ item1           value 1"), "{:?}", t[3]);
        assert_eq!(t[4], "");
        assert_eq!(t[5].trim_end(), "    item2           value 2");
    }

    #[test]
    fn a_heading_sits_directly_on_its_list() {
        let rows = vec![
            Row::Heading { text: "Services".into(), right: "8 of 8 running".into() },
            Row::entry("ingest", "running"),
        ];
        let mut scroll = Scroll::default();
        let t = text(&lines(&theme(), &rows, 0, &mut scroll, 13, 15));
        assert!(t[1].starts_with("    Services") && t[1].trim_end().ends_with("8 of 8 running"), "{:?}", t[1]);
        assert!(t[2].starts_with("  ▸ ingest"));
    }

    #[test]
    fn scrolling_moves_one_row_and_the_counts_follow() {
        let rows = rows(8);
        let mut scroll = Scroll::default();
        // 11 lines: a gap/hint line, five entries with gaps (9), a hint line.
        let t = text(&lines(&theme(), &rows, 4, &mut scroll, 11, 15));
        assert_eq!(t[0], "");
        assert!(t[9].starts_with("  ▸ item4"));
        assert_eq!(t[10].trim_end(), "    ⭣ 3 more");
        let t = text(&lines(&theme(), &rows, 5, &mut scroll, 11, 15));
        assert_eq!(t[0].trim_end(), "    ⭡ 1 more");
        assert!(t[9].starts_with("  ▸ item5"));
        assert_eq!(t[10].trim_end(), "    ⭣ 2 more");
        let t = text(&lines(&theme(), &rows, 7, &mut scroll, 11, 15));
        assert_eq!(t[0].trim_end(), "    ⭡ 3 more");
        assert_eq!(t[10], "");
        let t = text(&lines(&theme(), &rows, 2, &mut scroll, 11, 15));
        assert!(t.iter().any(|l| l.starts_with("  ▸ item2")), "going up scrolls back: {t:?}");
    }
}
