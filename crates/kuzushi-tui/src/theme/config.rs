//! M4 §4.1 — theme configuration. Operator-visible knobs:
//! `high_contrast` flips the palette to bright white on the terminal
//! background and removes dim styles; `NO_COLOR` disables semantic foreground
//! colours; `reduced_motion` pauses the spinner ticker for accessibility.
//!
//! Config sources, in precedence order:
//!   1. `KUZUSHI_THEME=high-contrast` env var (or `default`)
//!   2. `NO_COLOR` disables colour while preserving text markers/modifiers
//!   3. `KUZUSHI_REDUCED_MOTION=1|true|yes`
//!   4. Future: `~/.config/kuzushi/theme.toml` (deferred until an
//!      operator asks for per-color overrides — env vars cover the
//!      accessibility wins this milestone targets).
//!
//! The active config is exposed via [`active_theme`], lazily
//! initialised on first read. Mutating after first read is a no-op so
//! the rest of the render pipeline can treat it as effectively const.

#[cfg(not(test))]
use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorDepth {
    TrueColor,
    Ansi256,
    Ansi16,
    None,
}

impl Default for ColorDepth {
    fn default() -> Self {
        Self::TrueColor
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThemeConfig {
    pub high_contrast: bool,
    pub no_color: bool,
    pub reduced_motion: bool,
    pub color_depth: ColorDepth,
}

impl ThemeConfig {
    /// Read the active theme preference from environment variables. Used
    /// to seed the `OnceLock` at startup; tests construct values
    /// directly via the public field assignment.
    pub fn from_env() -> Self {
        Self::from_env_values(
            std::env::var("KUZUSHI_THEME").ok().as_deref(),
            std::env::var_os("NO_COLOR").is_some(),
            std::env::var("KUZUSHI_REDUCED_MOTION").ok().as_deref(),
            std::env::var("COLORTERM").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
        )
    }

    pub fn from_env_values(
        theme: Option<&str>,
        no_color_present: bool,
        reduced_motion: Option<&str>,
        color_term: Option<&str>,
        term: Option<&str>,
    ) -> Self {
        let color_depth = color_depth_from_values(no_color_present, color_term, term);
        Self {
            high_contrast: high_contrast_from_value(theme),
            no_color: color_depth == ColorDepth::None,
            reduced_motion: reduced_motion_from_value(reduced_motion),
            color_depth,
        }
    }
}

fn high_contrast_from_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case("high-contrast"))
}

fn reduced_motion_from_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn color_depth_from_values(
    no_color_present: bool,
    color_term: Option<&str>,
    term: Option<&str>,
) -> ColorDepth {
    if no_color_present || term_lacks_color(term) {
        return ColorDepth::None;
    }
    color_depth_for_capable_terminal(color_term, term)
}

fn color_depth_for_capable_terminal(color_term: Option<&str>, term: Option<&str>) -> ColorDepth {
    if value_mentions_truecolor(color_term) || value_mentions_truecolor(term) {
        return ColorDepth::TrueColor;
    }
    if value_contains(term, "256color") {
        return ColorDepth::Ansi256;
    }
    ColorDepth::Ansi16
}

fn term_lacks_color(term: Option<&str>) -> bool {
    term.is_none_or(term_is_blank_or_dumb)
}

fn term_is_blank_or_dumb(term: &str) -> bool {
    term.trim().is_empty() || term.trim().eq_ignore_ascii_case("dumb")
}

fn value_mentions_truecolor(value: Option<&str>) -> bool {
    value_contains(value, "truecolor") || value_contains(value, "24bit")
}

fn value_contains(value: Option<&str>, needle: &str) -> bool {
    value.is_some_and(|value| value.to_ascii_lowercase().contains(needle))
}

#[cfg(not(test))]
static ACTIVE_THEME: OnceLock<ThemeConfig> = OnceLock::new();

/// Return the active theme, lazily seeded from env vars on first read.
/// Idempotent — repeat calls in the same process see the same config.
#[cfg(not(test))]
pub fn active_theme() -> ThemeConfig {
    *ACTIVE_THEME.get_or_init(ThemeConfig::from_env)
}

/// Unit tests should not depend on the developer's shell theme env. Tests that
/// need alternate palettes exercise the pure `*_for_config` helpers directly.
#[cfg(test)]
pub fn active_theme() -> ThemeConfig {
    ThemeConfig::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_baseline() {
        let config = ThemeConfig::default();
        assert!(!config.high_contrast);
        assert!(!config.no_color);
        assert!(!config.reduced_motion);
        assert_eq!(config.color_depth, ColorDepth::TrueColor);
    }

    #[test]
    fn high_contrast_env_is_case_insensitive() {
        assert!(high_contrast_from_value(Some("High-Contrast")));
        assert!(high_contrast_from_value(Some(" high-contrast ")));
        assert!(!high_contrast_from_value(Some("default")));
        assert!(!high_contrast_from_value(None));
    }

    #[test]
    fn reduced_motion_env_accepts_common_truthy_values() {
        for value in ["1", "true", "TRUE", "yes", "on"] {
            assert!(
                reduced_motion_from_value(Some(value)),
                "expected {value:?} to enable reduced_motion"
            );
        }
        assert!(!reduced_motion_from_value(Some("0")));
        assert!(!reduced_motion_from_value(None));
    }

    #[test]
    fn no_color_env_uses_standard_presence_semantics() {
        assert_eq!(
            ThemeConfig::from_env_values(
                None,
                true,
                None,
                Some("truecolor"),
                Some("xterm-256color")
            )
            .color_depth,
            ColorDepth::None
        );
        assert!(ThemeConfig::from_env_values(None, true, None, Some("truecolor"), None).no_color);
    }

    #[test]
    fn color_depth_uses_terminal_capabilities() {
        assert_eq!(
            ThemeConfig::from_env_values(None, false, None, Some("truecolor"), Some("xterm"))
                .color_depth,
            ColorDepth::TrueColor
        );
        assert_eq!(
            ThemeConfig::from_env_values(None, false, None, None, Some("xterm-256color"))
                .color_depth,
            ColorDepth::Ansi256
        );
        assert_eq!(
            ThemeConfig::from_env_values(None, false, None, None, Some("vt100")).color_depth,
            ColorDepth::Ansi16
        );
        assert_eq!(
            ThemeConfig::from_env_values(None, false, None, None, Some("dumb")).color_depth,
            ColorDepth::None
        );
    }
}
