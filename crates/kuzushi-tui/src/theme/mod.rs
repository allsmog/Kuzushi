use super::*;
use crate::ui_view_models::SeverityTone;
use ratatui::prelude::{Color, Modifier, Style};

mod config;
pub use config::{active_theme, ThemeConfig};

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
// A calm slate distinct from T_ACCENT — low-severity text used to share the
// accent blue, so a selected low row (fg accent on bg accent) was unreadable.
pub const SEV_LOW: Color = Color::Rgb(0x8a, 0xa6, 0xc4);

pub fn primary() -> Style {
    if active_theme().high_contrast {
        return Style::default().fg(T_HEADING).add_modifier(Modifier::BOLD);
    }
    Style::default().fg(T_PRIMARY)
}

pub fn muted() -> Style {
    if active_theme().high_contrast {
        return Style::default().fg(T_PRIMARY);
    }
    Style::default().fg(T_MUTED)
}

pub fn disabled() -> Style {
    disabled_for_config(active_theme())
}

fn disabled_for_config(config: ThemeConfig) -> Style {
    if config.high_contrast {
        return Style::default().fg(T_PRIMARY);
    }
    Style::default().fg(T_MUTED).add_modifier(Modifier::DIM)
}

pub fn subtle() -> Style {
    if active_theme().high_contrast {
        return Style::default().fg(T_MUTED);
    }
    Style::default().fg(T_SUBTLE)
}

pub fn label() -> Style {
    if active_theme().high_contrast {
        return Style::default().fg(T_HEADING).add_modifier(Modifier::BOLD);
    }
    Style::default().fg(T_LABEL).add_modifier(Modifier::BOLD)
}

pub fn heading() -> Style {
    Style::default().fg(T_HEADING).add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    if active_theme().high_contrast {
        return Style::default().fg(T_HEADING).add_modifier(Modifier::BOLD);
    }
    Style::default().fg(T_ACCENT)
}

pub fn success() -> Style {
    Style::default()
        .fg(T_SUCCESS)
        .add_modifier(if active_theme().high_contrast {
            Modifier::BOLD
        } else {
            Modifier::empty()
        })
}

pub fn warn() -> Style {
    Style::default()
        .fg(T_WARN)
        .add_modifier(if active_theme().high_contrast {
            Modifier::BOLD
        } else {
            Modifier::empty()
        })
}

pub fn danger() -> Style {
    Style::default()
        .fg(T_DANGER)
        .add_modifier(if active_theme().high_contrast {
            Modifier::BOLD
        } else {
            Modifier::empty()
        })
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

pub(crate) fn severity_tone(tone: SeverityTone) -> Style {
    severity_tone_for_config(tone, active_theme())
}

fn severity_tone_for_config(tone: SeverityTone, config: ThemeConfig) -> Style {
    if config.high_contrast {
        return high_contrast_severity_tone(tone);
    }
    match tone {
        SeverityTone::Critical => Style::default()
            .fg(SEV_CRITICAL)
            .add_modifier(Modifier::BOLD),
        SeverityTone::High => Style::default().fg(SEV_HIGH),
        SeverityTone::Medium => Style::default().fg(SEV_MEDIUM),
        SeverityTone::Low | SeverityTone::Info => Style::default().fg(SEV_LOW),
        SeverityTone::Unknown => Style::default().fg(T_MUTED),
    }
}

fn high_contrast_severity_tone(tone: SeverityTone) -> Style {
    match tone {
        SeverityTone::Critical | SeverityTone::High => {
            Style::default().fg(T_DANGER).add_modifier(Modifier::BOLD)
        }
        SeverityTone::Medium => Style::default().fg(T_WARN).add_modifier(Modifier::BOLD),
        SeverityTone::Low | SeverityTone::Info => {
            Style::default().fg(T_HEADING).add_modifier(Modifier::BOLD)
        }
        SeverityTone::Unknown => Style::default().fg(T_PRIMARY),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_contrast_severity_tones_do_not_use_dim_default_palette() {
        let config = ThemeConfig {
            high_contrast: true,
            reduced_motion: false,
        };

        assert_eq!(
            severity_tone_for_config(SeverityTone::Low, config),
            Style::default().fg(T_HEADING).add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            severity_tone_for_config(SeverityTone::Info, config),
            Style::default().fg(T_HEADING).add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            severity_tone_for_config(SeverityTone::High, config),
            Style::default().fg(T_DANGER).add_modifier(Modifier::BOLD)
        );
    }

    #[test]
    fn disabled_style_does_not_dim_high_contrast_text() {
        let style = disabled_for_config(ThemeConfig {
            high_contrast: true,
            reduced_motion: false,
        });

        assert!(!style.add_modifier.contains(Modifier::DIM));
    }
}
