use super::*;
use crate::ui_view_models::SeverityTone;
use ratatui::prelude::{Color, Modifier, Style};

mod config;
pub use config::{active_theme, ColorDepth, ThemeConfig};

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
    let config = active_theme();
    if config.no_color {
        return Style::default();
    }
    if config.high_contrast {
        return fg(Style::default(), T_HEADING, config).add_modifier(Modifier::BOLD);
    }
    fg(Style::default(), T_PRIMARY, config)
}

pub fn muted() -> Style {
    let config = active_theme();
    if config.no_color {
        return Style::default();
    }
    if config.high_contrast {
        return fg(Style::default(), T_PRIMARY, config);
    }
    fg(Style::default(), T_MUTED, config)
}

pub fn disabled() -> Style {
    disabled_for_config(active_theme())
}

fn disabled_for_config(config: ThemeConfig) -> Style {
    if config.no_color {
        return Style::default().add_modifier(Modifier::DIM);
    }
    if config.high_contrast {
        return fg(Style::default(), T_PRIMARY, config);
    }
    fg(Style::default(), T_MUTED, config).add_modifier(Modifier::DIM)
}

pub fn subtle() -> Style {
    subtle_for_config(active_theme())
}

fn subtle_for_config(config: ThemeConfig) -> Style {
    if config.no_color {
        return Style::default().add_modifier(Modifier::DIM);
    }
    if config.high_contrast {
        return fg(Style::default(), T_MUTED, config);
    }
    let style = fg(Style::default(), T_SUBTLE, config);
    if config.color_depth == ColorDepth::Ansi16 {
        style.add_modifier(Modifier::DIM)
    } else {
        style
    }
}

pub fn label() -> Style {
    let config = active_theme();
    if config.no_color {
        return Style::default().add_modifier(Modifier::BOLD);
    }
    if config.high_contrast {
        return fg(Style::default(), T_HEADING, config).add_modifier(Modifier::BOLD);
    }
    fg(Style::default(), T_LABEL, config).add_modifier(Modifier::BOLD)
}

pub fn heading() -> Style {
    let config = active_theme();
    if config.no_color {
        return Style::default().add_modifier(Modifier::BOLD);
    }
    fg(Style::default(), T_HEADING, config).add_modifier(Modifier::BOLD)
}

pub fn accent() -> Style {
    let config = active_theme();
    if config.no_color {
        return Style::default().add_modifier(Modifier::BOLD);
    }
    if config.high_contrast {
        return fg(Style::default(), T_HEADING, config).add_modifier(Modifier::BOLD);
    }
    fg(Style::default(), T_ACCENT, config).add_modifier(Modifier::BOLD)
}

pub fn success() -> Style {
    let config = active_theme();
    if config.no_color {
        return Style::default().add_modifier(Modifier::BOLD);
    }
    fg(Style::default(), T_SUCCESS, config).add_modifier(if config.high_contrast {
        Modifier::BOLD
    } else {
        Modifier::empty()
    })
}

pub fn warn() -> Style {
    let config = active_theme();
    if config.no_color {
        return Style::default().add_modifier(Modifier::BOLD);
    }
    fg(Style::default(), T_WARN, config).add_modifier(if config.high_contrast {
        Modifier::BOLD
    } else {
        Modifier::empty()
    })
}

pub fn danger() -> Style {
    let config = active_theme();
    if config.no_color {
        return Style::default().add_modifier(Modifier::BOLD);
    }
    fg(Style::default(), T_DANGER, config).add_modifier(if config.high_contrast {
        Modifier::BOLD
    } else {
        Modifier::empty()
    })
}

/// Style for the proof/confidence chip. Mirrors `proof_detail_style`
/// (success/accent/muted/danger) so the chip and the detail pane read the same:
/// green = verified, blue = static support, grey = honest "we don't know",
/// dim = dismissed.
pub fn proof_confidence_tone(confidence: kuzushi_core::ProofConfidence) -> Style {
    use kuzushi_core::ProofConfidence;
    match confidence {
        ProofConfidence::Confirmed => success(),
        ProofConfidence::Likely => accent(),
        ProofConfidence::Unverified => muted(),
        ProofConfidence::Dismissed => disabled(),
    }
}

pub fn selection() -> Style {
    selection_for_config(active_theme())
}

fn selection_for_config(config: ThemeConfig) -> Style {
    if config.no_color {
        return Style::default().add_modifier(Modifier::REVERSED);
    }
    bg(fg(Style::default(), TERM_BG, config), T_ACCENT, config).add_modifier(Modifier::BOLD)
}

/// Inverse cursor block for the input prompt. Matches the mockup's
/// `<span style={{background: var(--t-primary), color: var(--term-bg)}}>`
/// cursor cell — softer than `selection()` since the prompt is always
/// visible and shouldn't pulse the same way a row selection does.
pub fn cursor_block() -> Style {
    let config = active_theme();
    if config.no_color {
        return Style::default().add_modifier(Modifier::REVERSED);
    }
    bg(fg(Style::default(), TERM_BG, config), T_PRIMARY, config)
}

pub(crate) fn severity_tone(tone: SeverityTone) -> Style {
    severity_tone_for_config(tone, active_theme())
}

fn severity_tone_for_config(tone: SeverityTone, config: ThemeConfig) -> Style {
    match severity_palette(config) {
        SeverityPalette::NoColor => no_color_severity_tone(tone),
        SeverityPalette::HighContrast => high_contrast_severity_tone(tone, config),
        SeverityPalette::Ansi16 => ansi16_severity_tone(tone),
        SeverityPalette::Standard => standard_severity_tone(tone, config),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeverityPalette {
    NoColor,
    HighContrast,
    Ansi16,
    Standard,
}

fn severity_palette(config: ThemeConfig) -> SeverityPalette {
    if config.no_color {
        return SeverityPalette::NoColor;
    }
    if config.high_contrast {
        return SeverityPalette::HighContrast;
    }
    if config.color_depth == ColorDepth::Ansi16 {
        return SeverityPalette::Ansi16;
    }
    SeverityPalette::Standard
}

fn standard_severity_tone(tone: SeverityTone, config: ThemeConfig) -> Style {
    match tone {
        SeverityTone::Critical => Style::default()
            .fg(adapt_color(SEV_CRITICAL, config))
            .add_modifier(Modifier::BOLD),
        SeverityTone::High => fg(Style::default(), SEV_HIGH, config),
        SeverityTone::Medium => fg(Style::default(), SEV_MEDIUM, config),
        SeverityTone::Low | SeverityTone::Info => fg(Style::default(), SEV_LOW, config),
        SeverityTone::Unknown => fg(Style::default(), T_MUTED, config),
    }
}

fn ansi16_severity_tone(tone: SeverityTone) -> Style {
    match tone {
        SeverityTone::Critical => Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        SeverityTone::High => Style::default().fg(Color::Red),
        SeverityTone::Medium => Style::default().fg(Color::Yellow),
        SeverityTone::Low => Style::default().fg(Color::Blue),
        SeverityTone::Info => Style::default().fg(Color::Cyan),
        SeverityTone::Unknown => Style::default().fg(Color::DarkGray),
    }
}

fn no_color_severity_tone(tone: SeverityTone) -> Style {
    match tone {
        SeverityTone::Critical | SeverityTone::High | SeverityTone::Medium => {
            Style::default().add_modifier(Modifier::BOLD)
        }
        SeverityTone::Low | SeverityTone::Info | SeverityTone::Unknown => Style::default(),
    }
}

fn high_contrast_severity_tone(tone: SeverityTone, config: ThemeConfig) -> Style {
    match tone {
        SeverityTone::Critical | SeverityTone::High => {
            fg(Style::default(), T_DANGER, config).add_modifier(Modifier::BOLD)
        }
        SeverityTone::Medium => fg(Style::default(), T_WARN, config).add_modifier(Modifier::BOLD),
        SeverityTone::Low | SeverityTone::Info => {
            fg(Style::default(), T_HEADING, config).add_modifier(Modifier::BOLD)
        }
        SeverityTone::Unknown => fg(Style::default(), T_PRIMARY, config),
    }
}

fn fg(style: Style, color: Color, config: ThemeConfig) -> Style {
    style.fg(adapt_color(color, config))
}

fn bg(style: Style, color: Color, config: ThemeConfig) -> Style {
    style.bg(adapt_color(color, config))
}

fn adapt_color(color: Color, config: ThemeConfig) -> Color {
    match config.color_depth {
        ColorDepth::TrueColor => color,
        ColorDepth::Ansi256 => ansi256_color(color),
        ColorDepth::Ansi16 | ColorDepth::None => ansi16_color(color),
    }
}

fn ansi256_color(color: Color) -> Color {
    match color {
        T_PRIMARY => Color::Indexed(188),
        T_MUTED => Color::Indexed(102),
        T_SUBTLE => Color::Indexed(60),
        T_ACCENT => Color::Indexed(111),
        T_LABEL => Color::Indexed(153),
        T_HEADING => Color::Indexed(15),
        T_SUCCESS => Color::Indexed(71),
        T_WARN => Color::Indexed(179),
        T_DANGER => Color::Indexed(167),
        TERM_BG => Color::Indexed(232),
        SEV_HIGH => Color::Indexed(210),
        SEV_LOW => Color::Indexed(109),
        _ => color,
    }
}

fn ansi16_color(color: Color) -> Color {
    match color {
        T_PRIMARY | T_HEADING => Color::White,
        T_MUTED | T_SUBTLE => Color::DarkGray,
        T_ACCENT | SEV_LOW => Color::Blue,
        T_LABEL => Color::Cyan,
        T_SUCCESS => Color::Green,
        T_WARN => Color::Yellow,
        T_DANGER | SEV_HIGH => Color::Red,
        TERM_BG => Color::Black,
        _ => color,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn high_contrast_severity_tones_do_not_use_dim_default_palette() {
        let config = ThemeConfig {
            high_contrast: true,
            no_color: false,
            reduced_motion: false,
            color_depth: ColorDepth::TrueColor,
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
            no_color: false,
            reduced_motion: false,
            color_depth: ColorDepth::TrueColor,
        });

        assert!(!style.add_modifier.contains(Modifier::DIM));
    }

    #[test]
    fn no_color_theme_uses_modifiers_not_foreground_colours() {
        let config = ThemeConfig {
            high_contrast: false,
            no_color: true,
            reduced_motion: false,
            color_depth: ColorDepth::None,
        };

        assert_eq!(
            severity_tone_for_config(SeverityTone::High, config),
            Style::default().add_modifier(Modifier::BOLD)
        );
        assert_eq!(
            severity_tone_for_config(SeverityTone::Low, config),
            Style::default()
        );
        assert_eq!(
            disabled_for_config(config),
            Style::default().add_modifier(Modifier::DIM)
        );
        assert_eq!(
            selection_for_config(config),
            Style::default().add_modifier(Modifier::REVERSED)
        );
    }

    #[test]
    fn theme_colours_downsample_for_limited_terminals() {
        let config = ThemeConfig {
            high_contrast: false,
            no_color: false,
            reduced_motion: false,
            color_depth: ColorDepth::Ansi16,
        };

        assert_eq!(
            severity_tone_for_config(SeverityTone::High, config).fg,
            Some(Color::Red)
        );
        assert!(!severity_tone_for_config(SeverityTone::High, config)
            .add_modifier
            .contains(Modifier::BOLD));
        assert_eq!(
            severity_tone_for_config(SeverityTone::Critical, config).fg,
            Some(Color::Red)
        );
        assert!(severity_tone_for_config(SeverityTone::Critical, config)
            .add_modifier
            .contains(Modifier::BOLD));
        assert_eq!(fg(Style::default(), T_ACCENT, config).fg, Some(Color::Blue));
        assert!(subtle_for_config(config)
            .add_modifier
            .contains(Modifier::DIM));
        assert_eq!(selection_for_config(config).bg, Some(Color::Blue));
    }

    #[test]
    fn selection_remains_visible_in_truecolor_and_high_contrast() {
        let truecolor = ThemeConfig::default();
        let high_contrast = ThemeConfig {
            high_contrast: true,
            ..ThemeConfig::default()
        };

        assert_eq!(selection_for_config(truecolor).bg, Some(T_ACCENT));
        assert_eq!(selection_for_config(high_contrast).bg, Some(T_ACCENT));
        assert!(selection_for_config(high_contrast)
            .add_modifier
            .contains(Modifier::BOLD));
    }

    #[test]
    fn ansi16_severity_tones_do_not_collapse() {
        let config = ThemeConfig {
            high_contrast: false,
            no_color: false,
            reduced_motion: false,
            color_depth: ColorDepth::Ansi16,
        };
        let tones = [
            SeverityTone::Critical,
            SeverityTone::High,
            SeverityTone::Medium,
            SeverityTone::Low,
            SeverityTone::Info,
            SeverityTone::Unknown,
        ];
        let styles = tones
            .into_iter()
            .map(|tone| (tone, severity_tone_for_config(tone, config)))
            .collect::<Vec<_>>();

        for (left_index, (left_tone, left_style)) in styles.iter().enumerate() {
            for (right_tone, right_style) in styles.iter().skip(left_index + 1) {
                assert_ne!(
                    left_style, right_style,
                    "{left_tone:?} collapsed into {right_tone:?}"
                );
            }
        }
    }
}
