use kuzushi_core::Severity;
use ratatui::prelude::{Color, Modifier, Style};

pub const STATUS_SEPARATOR: &str = " · ";
pub const RULE_CHAR: &str = "─";

pub fn primary() -> Style {
    Style::default().fg(Color::LightBlue)
}

pub fn muted() -> Style {
    Style::default().fg(Color::Cyan)
}

pub fn subtle() -> Style {
    Style::default().fg(Color::Blue)
}

pub fn label() -> Style {
    primary().add_modifier(Modifier::BOLD)
}

pub fn heading() -> Style {
    label()
}

pub fn accent() -> Style {
    Style::default().fg(Color::LightBlue)
}

pub fn success() -> Style {
    Style::default().fg(Color::Green)
}

pub fn warn() -> Style {
    Style::default().fg(Color::Yellow)
}

pub fn danger() -> Style {
    Style::default().fg(Color::Red)
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
