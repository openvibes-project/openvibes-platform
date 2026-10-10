//! One frame for every screen (spec §2): logo, location line, exactly one
//! empty line, an optional title rule and one more empty line, the
//! content, and the bar. Legacy screens get only the location line.

use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Layout, Rect},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::{
    bar::{self, Bar},
    logo::{self, Header},
    theme::Theme,
};

pub const MIN_WIDTH: u16 = 80;
pub const MIN_HEIGHT: u16 = 24;

pub fn too_small(frame: &mut Frame) -> bool {
    let area = frame.area();
    if area.width >= MIN_WIDTH && area.height >= MIN_HEIGHT {
        return false;
    }
    let lines = vec![
        Line::raw(format!("This window is {}×{}.", area.width, area.height)),
        Line::raw(format!(
            "OpenVIBES needs at least {MIN_WIDTH}×{MIN_HEIGHT}:"
        )),
        Line::raw("make the window larger."),
    ];
    let top = area.height.saturating_sub(3) / 2;
    let rect = Rect {
        y: area.y + top,
        height: 3.min(area.height),
        ..area
    };
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), rect);
    true
}

pub fn draw(
    frame: &mut Frame,
    theme: &Theme,
    header: &Header,
    title: Option<&str>,
    bar: &Bar,
) -> Rect {
    let area = frame.area();
    let heading = if title.is_some() { 2 } else { 0 };
    let [top, _gap, head, content, bottom] = Layout::vertical([
        Constraint::Length(logo::ROWS),
        Constraint::Length(1),
        Constraint::Length(heading),
        Constraint::Min(0),
        Constraint::Length(bar::HEIGHT),
    ])
    .areas(area);
    frame.render_widget(Paragraph::new(logo::lines(theme, header)), top);
    if let Some(title) = title {
        let rule = "━".repeat(70usize.saturating_sub(title.chars().count()));
        let line = Line::from(vec![
            Span::raw("    "),
            Span::styled("━━ ", theme.rule()),
            Span::styled(title.to_owned(), theme.bold()),
            Span::styled(format!(" {rule}"), theme.rule()),
        ]);
        frame.render_widget(Paragraph::new(vec![line, Line::raw("")]), head);
    }
    frame.render_widget(
        Paragraph::new(bar.lines(theme, area.width).to_vec()),
        bottom,
    );
    content
}

pub fn legacy(frame: &mut Frame, theme: &Theme, header: &Header) -> Rect {
    let area = frame.area();
    let [top, rest] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(area);
    frame.render_widget(Paragraph::new(logo::location_line(theme, header)), top);
    rest
}

#[cfg(test)]
mod tests {
    use ratatui::{Terminal, backend::TestBackend};

    use super::*;
    use crate::tui::ui::logo::Header;

    fn render(w: u16, h: u16, title: Option<&str>) -> (Vec<String>, Rect) {
        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
        let mut area = Rect::default();
        terminal
            .draw(|f| {
                if !too_small(f) {
                    let header = Header {
                        location: "limebox · Status",
                        version: "v0.2.8",
                        update: None,
                    };
                    area = draw(
                        f,
                        &Theme::new(None, Some("xterm")),
                        &header,
                        title,
                        &Bar::keys(&[]),
                    );
                }
            })
            .unwrap();
        let b = terminal.backend().buffer();
        let rows = (0..b.area.height)
            .map(|y| {
                (0..b.area.width)
                    .map(|x| b[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect();
        (rows, area)
    }

    #[test]
    fn logo_location_one_empty_line_then_the_title_and_one_more() {
        let (rows, area) = render(80, 24, Some("Status"));
        assert!(rows[6].starts_with("    limebox · Status"));
        assert_eq!(
            rows[7].trim(),
            "",
            "exactly one empty line under the location line"
        );
        assert!(rows[8].starts_with("    ━━ Status ━━"), "{:?}", rows[8]);
        assert_eq!(rows[9].trim(), "");
        assert_eq!(area.y, 10);
        assert_eq!(area.height, 24 - 10 - 3);
        assert!(rows[22].contains("Move"));
    }

    #[test]
    fn a_small_window_gets_one_sentence() {
        let (rows, _) = render(60, 18, None);
        let all = rows.join("\n");
        assert!(all.contains("This window is 60×18."), "{all}");
        assert!(all.contains("OpenVIBES needs at least 80×24:"));
    }
}
