//! The OpenVIBES wordmark every screen shows (spec §5, "the interface comes
//! first"): figlet's standard font, "Open" in white and "VIBES" in the brand
//! teal (a solid colour: the logo's gradient stays brand artwork), the tabs
//! on the row of the "p"'s descender, the version on the right.
//! Six rows; plain text without colour (`NO_COLOR`), so nothing depends on
//! it.

use platform_host::Host;
use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};

use super::app::{App, Tab};

/// Rows the banner takes.
pub const HEIGHT: u16 = 6;
/// The middle of the brand gradient (`docs/brand`, #37a7eb → #42d2c5).
pub const TEAL: Color = Color::Rgb(0x36, 0xb9, 0xe0);

const OPEN: [&str; 6] = [
    "  ___                  ",
    r" / _ \ _ __   ___ _ __  ",
    r"| | | | '_ \ / _ \ '_ \ ",
    r"| |_| | |_) |  __/ | | |",
    r" \___/| .__/ \___|_| |_|",
    r"      |_|               ",
];
const VIBES: [&str; 5] = [
    r"__     _____ ____  _____ ____ ",
    r"\ \   / /_ _| __ )| ____/ ___|",
    r" \ \ / / | ||  _ \|  _| \___ \",
    r"  \ V /  | || |_) | |___ ___) |",
    r"   \_/  |___|____/|_____|____/",
];

pub fn draw<H: Host>(frame: &mut Frame, area: Rect, app: &App<H>) {
    let paint = |style: Style| if app.color { style } else { Style::new() };
    let open = paint(Style::new().fg(Color::White).add_modifier(Modifier::BOLD));
    let vibes = paint(Style::new().fg(TEAL).add_modifier(Modifier::BOLD));
    let dim = paint(Style::new().add_modifier(Modifier::DIM));
    let current = Style::new().add_modifier(Modifier::REVERSED | Modifier::BOLD);
    let mut lines: Vec<Line> = (0..5)
        .map(|row| {
            Line::from(vec![
                Span::raw(" "),
                Span::styled(OPEN[row], open),
                Span::raw(" "),
                Span::styled(VIBES[row], vibes),
            ])
        })
        .collect();
    let mut last = vec![
        Span::raw(" "),
        Span::styled(OPEN[5].trim_end(), open),
        Span::raw("   "),
    ];
    for (tab, name) in [
        (Tab::Setup, "Setup"),
        (Tab::Services, "Services"),
        (Tab::Configuration, "Configuration"),
    ] {
        last.push(if tab == app.tab {
            Span::styled(format!("[{name}]"), current)
        } else {
            Span::styled(format!(" {name} "), dim)
        });
        last.push(Span::raw(" "));
    }
    lines.push(Line::from(last));
    frame.render_widget(Paragraph::new(lines), area);
    // The version, right-aligned beside the wordmark.
    let about = format!("v{} ", env!("CARGO_PKG_VERSION"));
    let width = u16::try_from(about.chars().count()).unwrap_or(area.width);
    if width + 58 <= area.width {
        let right = Rect::new(area.x + area.width - width, area.y + 1, width, 1);
        frame.render_widget(Paragraph::new(about).style(dim), right);
    }
}
