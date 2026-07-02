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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThemeConfig {
    pub high_contrast: bool,
    pub no_color: bool,
    pub reduced_motion: bool,
}

impl ThemeConfig {
    /// Read the active theme preference from environment variables. Used
    /// to seed the `OnceLock` at startup; tests construct values
    /// directly via the public field assignment.
    pub fn from_env() -> Self {
        Self {
            high_contrast: high_contrast_from_env(),
            no_color: no_color_from_env(),
            reduced_motion: reduced_motion_from_env(),
        }
    }
}

fn high_contrast_from_env() -> bool {
    high_contrast_from_value(std::env::var("KUZUSHI_THEME").ok().as_deref())
}

fn high_contrast_from_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| value.trim().eq_ignore_ascii_case("high-contrast"))
}

fn no_color_from_env() -> bool {
    no_color_from_presence(std::env::var_os("NO_COLOR").is_some())
}

fn no_color_from_presence(present: bool) -> bool {
    present
}

fn reduced_motion_from_env() -> bool {
    reduced_motion_from_value(std::env::var("KUZUSHI_REDUCED_MOTION").ok().as_deref())
}

fn reduced_motion_from_value(value: Option<&str>) -> bool {
    value.is_some_and(|value| {
        matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
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
        assert!(no_color_from_presence(true));
        assert!(!no_color_from_presence(false));
    }
}
