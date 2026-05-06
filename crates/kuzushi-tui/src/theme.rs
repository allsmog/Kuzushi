use kuzushi_core::Severity;
use ratatui::prelude::{Color, Modifier, Style};

pub const STATUS_SEPARATOR: &str = " · ";
pub const RULE_CHAR: &str = "─";

pub fn primary() -> Style {
    Style::default().fg(Color::Rgb(207, 214, 224))
}

pub fn muted() -> Style {
    Style::default().fg(Color::Rgb(125, 135, 148))
}

pub fn subtle() -> Style {
    Style::default().fg(Color::Rgb(61, 70, 84))
}

pub fn label() -> Style {
    Style::default()
        .fg(Color::Rgb(166, 205, 255))
        .add_modifier(Modifier::BOLD)
}

pub fn heading() -> Style {
    Style::default()
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    Style::default().fg(Color::Rgb(127, 184, 255))
}

pub fn success() -> Style {
    Style::default().fg(Color::Rgb(87, 196, 121))
}

pub fn warn() -> Style {
    Style::default().fg(Color::Rgb(226, 193, 74))
}

pub fn danger() -> Style {
    Style::default().fg(Color::Rgb(226, 92, 92))
}

pub fn selection() -> Style {
    Style::default()
        .fg(Color::Black)
        .bg(Color::LightBlue)
        .add_modifier(Modifier::BOLD)
}

pub fn severity(severity: Severity) -> Style {
    match severity {
        Severity::Critical => danger().add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(Color::LightRed),
        Severity::Medium => warn(),
        Severity::Low | Severity::Info => accent(),
        Severity::Unknown => muted(),
    }
}

pub fn severity_glyph(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "█",
        Severity::High => "▆",
        Severity::Medium => "▄",
        Severity::Low => "▂",
        Severity::Info => "▁",
        Severity::Unknown => "·",
    }
}
