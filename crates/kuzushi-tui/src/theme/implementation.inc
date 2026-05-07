use kuzushi_core::Severity;
use ratatui::prelude::{Color, Modifier, Style};

pub const STATUS_SEPARATOR: &str = " · ";
pub const RULE_CHAR: &str = "─";

// Design palette (true-colour). See design/mockups/_shared.jsx.
pub const T_PRIMARY: Color = Color::Rgb(0xcf, 0xd6, 0xe0);
pub const T_MUTED: Color = Color::Rgb(0x7d, 0x87, 0x94);
pub const T_SUBTLE: Color = Color::Rgb(0x3d, 0x46, 0x54);
pub const T_ACCENT: Color = Color::Rgb(0x7f, 0xb8, 0xff);
pub const T_LABEL: Color = Color::Rgb(0xa6, 0xcd, 0xff);
pub const T_HEADING: Color = Color::Rgb(0xff, 0xff, 0xff);
pub const T_SUCCESS: Color = Color::Rgb(0x57, 0xc4, 0x79);
pub const T_WARN: Color = Color::Rgb(0xe2, 0xc1, 0x4a);
pub const T_DANGER: Color = Color::Rgb(0xe2, 0x5c, 0x5c);
pub const TERM_BG: Color = Color::Rgb(0x0b, 0x0d, 0x10);

pub const SEV_CRITICAL: Color = T_DANGER;
pub const SEV_HIGH: Color = Color::Rgb(0xff, 0x8b, 0x8b);
pub const SEV_MEDIUM: Color = T_WARN;
pub const SEV_LOW: Color = T_ACCENT;

pub fn primary() -> Style {
    Style::default().fg(T_PRIMARY)
}

pub fn muted() -> Style {
    Style::default().fg(T_MUTED)
}

pub fn subtle() -> Style {
    Style::default().fg(T_SUBTLE)
}

pub fn label() -> Style {
    Style::default().fg(T_LABEL).add_modifier(Modifier::BOLD)
}

pub fn heading() -> Style {
    Style::default().fg(T_HEADING).add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    Style::default().fg(T_ACCENT)
}

pub fn success() -> Style {
    Style::default().fg(T_SUCCESS)
}

pub fn warn() -> Style {
    Style::default().fg(T_WARN)
}

pub fn danger() -> Style {
    Style::default().fg(T_DANGER)
}

pub fn selection() -> Style {
    Style::default()
        .fg(TERM_BG)
        .bg(T_ACCENT)
        .add_modifier(Modifier::BOLD)
}

/// Inverse cursor block for the input prompt. Matches the mockup's
/// `<span style={{background: var(--t-primary), color: var(--term-bg)}}>`
/// cursor cell — softer than `selection()` since the prompt is always
/// visible and shouldn't pulse the same way a row selection does.
pub fn cursor_block() -> Style {
    Style::default().fg(TERM_BG).bg(T_PRIMARY)
}

pub fn severity(severity: Severity) -> Style {
    match severity {
        Severity::Critical => Style::default()
            .fg(SEV_CRITICAL)
            .add_modifier(Modifier::BOLD),
        Severity::High => Style::default().fg(SEV_HIGH),
        Severity::Medium => Style::default().fg(SEV_MEDIUM),
        Severity::Low | Severity::Info => Style::default().fg(SEV_LOW),
        Severity::Unknown => muted(),
    }
}
