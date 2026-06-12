//! M4 §4.1 — theme configuration. Operator-visible knobs:
//! `high_contrast` flips the palette to bright white on the terminal
//! background and removes dim styles; `reduced_motion` pauses the
//! spinner ticker for accessibility.
//!
//! Config sources, in precedence order:
//!   1. `KUZUSHI_THEME=high-contrast` env var (or `default`)
//!   2. `KUZUSHI_REDUCED_MOTION=1|true|yes`
//!   3. Future: `~/.config/kuzushi/theme.toml` (deferred until an
//!      operator asks for per-color overrides — env vars cover the
//!      accessibility wins this milestone targets).
//!
//! The active config is exposed via [`active_theme`], lazily
//! initialised on first read. Mutating after first read is a no-op so
//! the rest of the render pipeline can treat it as effectively const.

use std::sync::OnceLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThemeConfig {
    pub high_contrast: bool,
    pub reduced_motion: bool,
}

impl ThemeConfig {
    /// Read the active theme preference from environment variables. Used
    /// to seed the `OnceLock` at startup; tests construct values
    /// directly via the public field assignment.
    pub fn from_env() -> Self {
        Self {
            high_contrast: high_contrast_from_env(),
            reduced_motion: reduced_motion_from_env(),
        }
    }
}

fn high_contrast_from_env() -> bool {
    match std::env::var("KUZUSHI_THEME") {
        Ok(value) => value.trim().eq_ignore_ascii_case("high-contrast"),
        Err(_) => false,
    }
}

fn reduced_motion_from_env() -> bool {
    match std::env::var("KUZUSHI_REDUCED_MOTION") {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

static ACTIVE_THEME: OnceLock<ThemeConfig> = OnceLock::new();

/// Return the active theme, lazily seeded from env vars on first read.
/// Idempotent — repeat calls in the same process see the same config.
pub fn active_theme() -> ThemeConfig {
    *ACTIVE_THEME.get_or_init(ThemeConfig::from_env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_baseline() {
        let config = ThemeConfig::default();
        assert!(!config.high_contrast);
        assert!(!config.reduced_motion);
    }

    #[test]
    fn high_contrast_env_is_case_insensitive() {
        // SAFETY: tests run in the same process so KUZUSHI_THEME may be
        // observed by other code. Mutating env vars is unsafe in
        // multi-threaded tests; this is a focused single-threaded test.
        let prior = std::env::var("KUZUSHI_THEME").ok();
        // SAFETY: covered by the prior-restore dance below.
        unsafe {
            std::env::set_var("KUZUSHI_THEME", "High-Contrast");
        }
        let config = ThemeConfig::from_env();
        assert!(config.high_contrast);
        match prior {
            Some(value) => unsafe { std::env::set_var("KUZUSHI_THEME", value) },
            None => unsafe { std::env::remove_var("KUZUSHI_THEME") },
        }
    }

    #[test]
    fn reduced_motion_env_accepts_common_truthy_values() {
        for value in ["1", "true", "TRUE", "yes", "on"] {
            let prior = std::env::var("KUZUSHI_REDUCED_MOTION").ok();
            unsafe { std::env::set_var("KUZUSHI_REDUCED_MOTION", value) };
            let config = ThemeConfig::from_env();
            assert!(
                config.reduced_motion,
                "expected {value:?} to enable reduced_motion"
            );
            match prior {
                Some(prior) => unsafe { std::env::set_var("KUZUSHI_REDUCED_MOTION", prior) },
                None => unsafe { std::env::remove_var("KUZUSHI_REDUCED_MOTION") },
            }
        }
    }
}
