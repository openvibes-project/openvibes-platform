//! The approved logo (block letters, OPEN white, VIBES teal) and the
//! location line under it: where you are on the left, the version and any
//! available update on the right (spec §2).

use ratatui::text::{Line, Span};

use super::theme::Theme;

pub const ROWS: u16 = 7;
/// The column the location line ends at (the logo's right edge).
pub const RIGHT: usize = 76;
const INDENT: &str = "    ";

const OPEN: [&str; 6] = [
    " ██████╗ ██████╗ ███████╗███╗   ██╗",
    "██╔═══██╗██╔══██╗██╔════╝████╗  ██║",
    "██║   ██║██████╔╝█████╗  ██╔██╗ ██║",
    "██║   ██║██╔═══╝ ██╔══╝  ██║╚██╗██║",
    "╚██████╔╝██║     ███████╗██║ ╚████║",
    " ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═══╝",
];
const VIBES: [&str; 6] = [
    "██╗   ██╗██╗██████╗ ███████╗███████╗",
    "██║   ██║██║██╔══██╗██╔════╝██╔════╝",
    "██║   ██║██║██████╔╝█████╗  ███████╗",
    "╚██╗ ██╔╝██║██╔══██╗██╔══╝  ╚════██║",
    " ╚████╔╝ ██║██████╔╝███████╗███████║",
    "  ╚═══╝  ╚═╝╚═════╝ ╚══════╝╚══════╝",
];

pub struct Header<'a> {
    pub location: &'a str,
    pub version: &'a str,
    pub update: Option<&'a str>,
}

pub fn location_line(theme: &Theme, header: &Header) -> Line<'static> {
    let mut right = vec![Span::styled(header.version.to_owned(), theme.dim())];
    let mut right_len = header.version.chars().count();
    if let Some(update) = header.update {
        let notice = format!("  ▲ {update} available");
        right_len += notice.chars().count();
        right.push(Span::styled(notice, theme.yellow()));
    }
    let left = header.location.chars().count();
    let gap = RIGHT.saturating_sub(INDENT.len() + left + right_len).max(1);
    let mut spans = vec![
        Span::raw(INDENT),
        Span::styled(header.location.to_owned(), theme.dim()),
        Span::raw(" ".repeat(gap)),
    ];
    spans.extend(right);
    Line::from(spans)
}

pub fn lines(theme: &Theme, header: &Header) -> Vec<Line<'static>> {
    let mut out: Vec<Line> = OPEN
        .iter()
        .zip(VIBES)
        .map(|(open, vibes)| {
            Line::from(vec![
                Span::raw(INDENT),
                Span::styled(*open, theme.white()),
                Span::styled(vibes, theme.teal()),
            ])
        })
        .collect();
    out.push(location_line(theme, header));
    out
}

/// The plain text of `lines` (tests).
pub fn text(lines: &[Line]) -> Vec<String> {
    lines
        .iter()
        .map(|line| line.spans.iter().map(|span| span.content.as_ref()).collect())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(update: Option<&'static str>) -> Header<'static> {
        Header { location: "limebox · Maintenance › Certificates", version: "v0.2.8", update }
    }

    #[test]
    fn six_logo_rows_then_the_location_line_ending_at_column_76() {
        let theme = Theme::new(None, None);
        let text = text(&lines(&theme, &header(Some("0.2.9"))));
        assert_eq!(text.len(), 7);
        assert!(text[0].starts_with("     ██████╗ ██████╗"), "{:?}", text[0]);
        assert!(text[6].starts_with("    limebox · Maintenance › Certificates"));
        assert!(text[6].ends_with("v0.2.8  ▲ 0.2.9 available"), "{:?}", text[6]);
        assert_eq!(text[6].chars().count(), RIGHT);
    }

    #[test]
    fn no_update_shows_only_the_version() {
        let theme = Theme::new(None, None);
        let text = text(&lines(&theme, &header(None)));
        assert!(text[6].ends_with("v0.2.8") && !text[6].contains("available"));
        assert_eq!(text[6].chars().count(), RIGHT);
    }
}
