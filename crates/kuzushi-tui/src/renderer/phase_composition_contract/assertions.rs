use super::*;
use crate::theme::{self, CinematicLevel, ThemeConfig};
use ratatui::style::{Color, Modifier};

impl PhaseCompositionContract {
    pub(super) fn assert_buffer(self, buffer: &Buffer, text: &str, profile: TerminalProfile) {
        let _theme = theme::scoped_theme_for_test(profile.config());
        self.assert_semantic_content(text);
        self.assert_navigation_controls(text);
        assert!(text.contains('▸'), "{} needs a non-color marker", self.slug);
        assert_bounded_rails(text, self.slug);
        assert_one_accent_region(buffer, profile, self.slug);
        assert_profile_colors(buffer, profile);
    }

    pub(super) fn assert_plain_text(self, text: &str, width: u16) {
        self.assert_semantic_content(text);
        let flattened = collapse_whitespace(text);
        let command = self.plain_command_for_width(width);
        assert!(
            flattened.contains(command),
            "{} plain projection clipped command {:?}:\n{text}",
            self.slug,
            command
        );
        assert!(
            flattened.contains(self.plain_truth_atom()),
            "{} plain projection lost truthful state {:?}:\n{text}",
            self.slug,
            self.plain_truth_atom()
        );
    }

    pub(super) fn assert_plain_width(self, text: &str, width: u16) {
        let overlong = text
            .lines()
            .filter_map(|line| {
                let rendered_width = display_width(line);
                (rendered_width > width as usize).then_some((rendered_width, line))
            })
            .collect::<Vec<_>>();
        assert!(
            overlong.is_empty(),
            "{} plain projection exceeded {width} columns: {overlong:?}",
            self.slug
        );
    }

    fn assert_semantic_content(self, text: &str) {
        for section in self.sections {
            assert!(
                text.contains(section),
                "{} missing {section}:\n{text}",
                self.slug
            );
        }
        for priority in self.priority_atoms() {
            assert!(
                text.contains(&priority),
                "{} missing {priority}:\n{text}",
                self.slug
            );
        }
        assert!(!text.contains("[object Object]"), "{text}");
        assert!(!text.contains("undefined"), "{text}");
    }

    fn assert_navigation_controls(self, text: &str) {
        let flattened = collapse_whitespace(text);
        for control in ["Ctrl+C request abort", "Esc prompt", "NAVIGATION MODE"] {
            assert!(
                flattened.contains(control),
                "{} navigation projection lost {:?}:\n{text}",
                self.slug,
                control
            );
        }
    }

    fn priority_atoms(self) -> [String; 4] {
        [
            "KUZUSHI".to_string(),
            format!("view {}", self.phase.word()),
            "LIVE".to_string(),
            "NEXT".to_string(),
        ]
    }
}

fn collapse_whitespace(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn assert_bounded_rails(text: &str, phase: &str) {
    for row in text.lines() {
        let rails = row.chars().filter(|character| *character == '│').count();
        assert!(
            rails <= 16,
            "{phase} emitted {rails} rails on one row: {row}"
        );
    }
    assert!(!text.contains('┏'), "{phase} regressed to heavy pane boxes");
    assert!(!text.contains('┓'), "{phase} regressed to heavy pane boxes");
}

/// A selection band is the cockpit's primary interactive accent owner. Other
/// foreground accents remain semantic (NEXT, LIVE, severity, and meters), so
/// this invariant intentionally bounds selection backgrounds rather than
/// pretending every accent-colored span forms one contiguous region.
fn assert_one_accent_region(buffer: &Buffer, profile: TerminalProfile, phase: &str) {
    let config = profile.config();
    let selection = theme::selection();
    let regions = if config.no_color {
        style_region_count(buffer, |cell| cell.modifier.contains(Modifier::REVERSED))
    } else {
        let background = selection.bg.expect("colored selection background");
        style_region_count(buffer, |cell| cell.bg == background)
    };
    assert!(
        regions <= 1,
        "{phase} {}x{} {profile:?} owns {regions} selection accent regions",
        buffer.area.width,
        buffer.area.height
    );
}

fn style_region_count(buffer: &Buffer, matches: impl Fn(&ratatui::buffer::Cell) -> bool) -> usize {
    (0..buffer.area.height)
        .map(|y| row_region_count(buffer, y, &matches))
        .sum()
}

fn row_region_count(
    buffer: &Buffer,
    y: u16,
    matches: &impl Fn(&ratatui::buffer::Cell) -> bool,
) -> usize {
    let mut inside = false;
    let mut regions = 0;
    for x in 0..buffer.area.width {
        let matched = matches(&buffer[(x, y)]);
        regions += usize::from(matched && !inside);
        inside = matched;
    }
    regions
}

fn assert_profile_colors(buffer: &Buffer, profile: TerminalProfile) {
    let colors = buffer.content.iter().flat_map(|cell| [cell.fg, cell.bg]);
    match profile {
        TerminalProfile::TrueColor => assert_truecolor(colors),
        TerminalProfile::Indexed => assert_indexed(colors),
        TerminalProfile::HighContrast => assert_high_contrast(colors),
        TerminalProfile::NoColor => assert_no_color(colors),
    }
}

fn assert_truecolor(colors: impl Iterator<Item = Color> + Clone) {
    assert!(colors.clone().any(|color| matches!(color, Color::Rgb(..))));
    assert_eq!(theme::cinematic_profile().level, CinematicLevel::Full);
}

fn assert_indexed(colors: impl Iterator<Item = Color> + Clone) {
    assert!(colors
        .clone()
        .any(|color| matches!(color, Color::Indexed(_))));
    assert!(!colors.clone().any(|color| matches!(color, Color::Rgb(..))));
    assert_eq!(theme::cinematic_profile().level, CinematicLevel::Indexed);
}

fn assert_high_contrast(colors: impl Iterator<Item = Color> + Clone) {
    assert!(!colors.clone().any(is_cinematic_background));
    assert_eq!(theme::cinematic_profile().level, CinematicLevel::Off);
}

fn assert_no_color(colors: impl Iterator<Item = Color> + Clone) {
    assert!(colors.clone().all(|color| color == Color::Reset));
    assert_eq!(theme::cinematic_profile().level, CinematicLevel::Off);
}

fn is_cinematic_background(color: Color) -> bool {
    matches!(
        color,
        Color::Rgb(5, 10, 12) | Color::Rgb(7, 14, 17) | Color::Rgb(20, 43, 39)
    )
}
