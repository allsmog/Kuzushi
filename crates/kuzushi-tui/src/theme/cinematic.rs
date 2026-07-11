use super::{ColorDepth, ThemeConfig};
use ratatui::style::Color;

/// Amount of cinematic styling the active terminal can represent faithfully.
/// Accessibility themes deliberately opt out instead of approximating texture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CinematicLevel {
    Full,
    Indexed,
    Off,
}

/// Terminal-safe colors used by the phase cockpit's non-semantic backdrop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CinematicProfile {
    pub(crate) level: CinematicLevel,
    background: Option<Color>,
    scanline: Option<Color>,
    watermark: Option<Color>,
}

impl CinematicProfile {
    const FULL: Self = Self {
        level: CinematicLevel::Full,
        background: Some(Color::Rgb(5, 10, 12)),
        scanline: Some(Color::Rgb(7, 14, 17)),
        watermark: Some(Color::Rgb(20, 43, 39)),
    };

    const INDEXED: Self = Self {
        level: CinematicLevel::Indexed,
        background: Some(Color::Indexed(232)),
        scanline: Some(Color::Indexed(233)),
        watermark: Some(Color::Indexed(23)),
    };

    const OFF: Self = Self {
        level: CinematicLevel::Off,
        background: None,
        scanline: None,
        watermark: None,
    };

    pub(crate) const fn background(self) -> Option<Color> {
        self.background
    }

    pub(crate) const fn scanline(self) -> Option<Color> {
        self.scanline
    }

    pub(crate) const fn watermark(self) -> Option<Color> {
        self.watermark
    }

    pub(crate) const fn is_enabled(self) -> bool {
        !matches!(self.level, CinematicLevel::Off)
    }

    pub(crate) fn owns_background(self, color: Color) -> bool {
        color == Color::Reset || self.background == Some(color) || self.scanline == Some(color)
    }
}

pub(crate) fn cinematic_profile() -> CinematicProfile {
    cinematic_profile_for(super::active_theme())
}

pub(crate) const fn cinematic_profile_for(config: ThemeConfig) -> CinematicProfile {
    if config.high_contrast || config.no_color {
        return CinematicProfile::OFF;
    }
    match config.color_depth {
        ColorDepth::TrueColor => CinematicProfile::FULL,
        ColorDepth::Ansi256 => CinematicProfile::INDEXED,
        ColorDepth::Ansi16 | ColorDepth::None => CinematicProfile::OFF,
    }
}

/// Reduced motion controls animation only; it never changes palette fidelity.
pub(crate) const fn cinematic_motion_enabled(config: ThemeConfig) -> bool {
    !config.reduced_motion && cinematic_profile_for(config).is_enabled()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(color_depth: ColorDepth) -> ThemeConfig {
        ThemeConfig {
            color_depth,
            no_color: color_depth == ColorDepth::None,
            ..ThemeConfig::default()
        }
    }

    #[test]
    fn capability_selects_full_indexed_or_off_profile() {
        assert_eq!(
            cinematic_profile_for(config(ColorDepth::TrueColor)).level,
            CinematicLevel::Full
        );
        assert_eq!(
            cinematic_profile_for(config(ColorDepth::Ansi256)).level,
            CinematicLevel::Indexed
        );
        assert_eq!(
            cinematic_profile_for(config(ColorDepth::Ansi16)).level,
            CinematicLevel::Off
        );
        assert_eq!(
            cinematic_profile_for(config(ColorDepth::None)).level,
            CinematicLevel::Off
        );
    }

    #[test]
    fn accessibility_palettes_disable_cinematic_styling() {
        let high_contrast = ThemeConfig {
            high_contrast: true,
            ..config(ColorDepth::TrueColor)
        };
        let no_color = ThemeConfig {
            no_color: true,
            ..config(ColorDepth::TrueColor)
        };

        assert_eq!(
            cinematic_profile_for(high_contrast).level,
            CinematicLevel::Off
        );
        assert_eq!(cinematic_profile_for(no_color).level, CinematicLevel::Off);
    }

    #[test]
    fn indexed_profile_never_emits_rgb_colors() {
        let profile = cinematic_profile_for(config(ColorDepth::Ansi256));
        for color in [
            profile.background(),
            profile.scanline(),
            profile.watermark(),
        ] {
            assert!(matches!(color, Some(Color::Indexed(_))));
        }
    }

    #[test]
    fn reduced_motion_is_independent_from_profile_selection() {
        let moving = config(ColorDepth::TrueColor);
        let reduced = ThemeConfig {
            reduced_motion: true,
            ..moving
        };

        assert_eq!(
            cinematic_profile_for(moving),
            cinematic_profile_for(reduced)
        );
        assert!(cinematic_motion_enabled(moving));
        assert!(!cinematic_motion_enabled(reduced));
    }
}
