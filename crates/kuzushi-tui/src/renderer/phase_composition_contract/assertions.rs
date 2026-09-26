use super::*;
use crate::theme::{self, CinematicLevel, ThemeConfig};
use ratatui::style::{Color, Modifier};

impl PhaseCompositionContract {
    pub(super) fn assert_buffer(self, buffer: &Buffer, text: &str, profile: TerminalProfile) {
        let _theme = theme::scoped_theme_for_test(profile.config());
        self.assert_semantic_content(text, buffer.area.width);
        self.assert_navigation_controls(text);
        assert!(text.contains('▸'), "{} needs a non-color marker", self.slug);
        assert_bounded_rails(text, self.slug);
        assert_one_accent_region(buffer, profile, self.slug);
        assert_profile_colors(buffer, profile);
    }

    pub(super) fn assert_plain_text(self, text: &str, width: u16) {
        self.assert_semantic_content(text, width);
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

    fn assert_semantic_content(self, text: &str, width: u16) {
        self.assert_sections(text, width);
        self.assert_priority_atoms(text, width);
        assert!(!text.contains("[object Object]"), "{text}");
        assert!(!text.contains("undefined"), "{text}");
        self.assert_compact_content(text, width);
    }

    fn assert_sections(self, text: &str, width: u16) {
        for section in adaptive_sections(self.phase, width) {
            assert!(
                text.contains(section),
                "{} missing {section}:\n{text}",
                self.slug
            );
        }
    }

    fn assert_priority_atoms(self, text: &str, width: u16) {
        for priority in self.priority_atoms(width) {
            assert!(
                contains_contract_atom(text, &priority),
                "{} missing {priority}:\n{text}",
                self.slug
            );
        }
    }

    fn assert_compact_content(self, text: &str, width: u16) {
        if width >= 78 {
            return;
        }
        for atom in self.critical_compact_atoms() {
            assert!(
                contains_contract_atom(text, atom),
                "{} compact view missing {atom}:\n{text}",
                self.slug
            );
        }
        if self.phase == kuzushi_core::WorkflowPhase::Prove {
            assert!(
                text.contains("1src") || text.contains("source(s)"),
                "prove compact view lost the unique source count:\n{text}"
            );
        }
    }

    fn assert_navigation_controls(self, text: &str) {
        let flattened = collapse_whitespace(text);
        for control in [
            "Ctrl+C request abort",
            "Esc prompt",
            "NAVIGATE",
            "Shift+Tab ph",
        ] {
            assert!(
                flattened.contains(control),
                "{} navigation projection lost {:?}:\n{text}",
                self.slug,
                control
            );
        }
    }

    fn priority_atoms(self, width: u16) -> Vec<String> {
        let mut atoms = vec!["KUZUSHI".to_string(), "NEXT".to_string()];
        if width >= 50 {
            let mut slug = self.slug.chars();
            let title = match slug.next() {
                Some(first) => first.to_uppercase().collect::<String>() + slug.as_str(),
                None => String::new(),
            };
            atoms.push(format!("Viewing {title}"));
        }
        atoms
    }

    fn critical_compact_atoms(self) -> &'static [&'static str] {
        match self.phase {
            kuzushi_core::WorkflowPhase::Map => &["Viewing Map", "SYSTEM SUMMARY"],
            kuzushi_core::WorkflowPhase::Scan => &["Viewing Scan", "complete", "scan-phase"],
            // Compact Review reads as finding cards: identity and proof first.
            // The plain truth atom keeps guarding the source count, which a
            // card shows only when the viewport leaves it a row.
            kuzushi_core::WorkflowPhase::Review => &["FINDINGS", "F-0001", "[●●●]"],
            kuzushi_core::WorkflowPhase::Prove => &["F-0001", "STATUS", "NEXT", "[●●●]"],
            kuzushi_core::WorkflowPhase::Fix => {
                &["REMEDIATION", "Staged", "patch apply", "patch reject"]
            }
        }
    }
}

fn adaptive_sections(phase: kuzushi_core::WorkflowPhase, width: u16) -> &'static [&'static str] {
    use kuzushi_core::WorkflowPhase;
    match (phase, width >= 120, width >= 78) {
        (WorkflowPhase::Map, true, _) => &[
            "SYSTEM SUMMARY",
            "EXECUTIVE SUMMARY",
            "OVERALL DATA FLOW",
            "COMPONENT TREE",
        ],
        (WorkflowPhase::Map, false, true) => &["SYSTEM SUMMARY", "EXECUTIVE SUMMARY"],
        (WorkflowPhase::Map, false, false) => &["SYSTEM SUMMARY"],
        (WorkflowPhase::Scan, true, _) => &["ENGINE OUTCOMES", "SCAN RECEIPT", "SCOPE / PLAN"],
        (WorkflowPhase::Scan, false, true) => &["ENGINE OUTCOMES", "SCAN RECEIPT"],
        (WorkflowPhase::Scan, false, false) => &["ENGINE OUTCOMES"],
        (WorkflowPhase::Review, _, true) => &["FINDINGS", "SELECTED FINDING"],
        (WorkflowPhase::Review, _, false) => &["FINDINGS"],
        (WorkflowPhase::Prove, true, _) => &["STATUS / NEXT", "EVIDENCE", "PROOF LADDER"],
        (WorkflowPhase::Prove, false, true) => &["STATUS / NEXT", "EVIDENCE"],
        (WorkflowPhase::Prove, false, false) => &["STATUS / NEXT"],
        (WorkflowPhase::Fix, true, _) => &["REMEDIATION", "BREAKDOWN REPORT", "VERIFICATION"],
        (WorkflowPhase::Fix, false, true) => &["REMEDIATION", "BREAKDOWN REPORT"],
        (WorkflowPhase::Fix, false, false) => &["REMEDIATION"],
    }
}

/// Every spelling of the runtime-verified proof tier: the meter glyphs, their
/// ASCII fallback, and the words compact finding cards use.
const RUNTIME_PROOF_SPELLINGS: [&str; 3] = ["[●●●]", "[***]", "runtime verified"];

fn contains_contract_atom(text: &str, atom: &str) -> bool {
    if RUNTIME_PROOF_SPELLINGS.contains(&atom) {
        return RUNTIME_PROOF_SPELLINGS
            .iter()
            .any(|spelling| text.contains(spelling));
    }
    text.contains(atom)
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

/// Counts 4-connected regions, so one selected finding card spanning several
/// rows is one selection band while two separate bands still count twice.
fn style_region_count(buffer: &Buffer, matches: impl Fn(&ratatui::buffer::Cell) -> bool) -> usize {
    let mut unvisited = matching_cells(buffer, &matches);
    let mut regions = 0;
    while let Some(&start) = unvisited.iter().next() {
        remove_connected_region(&mut unvisited, start);
        regions += 1;
    }
    regions
}

fn matching_cells(
    buffer: &Buffer,
    matches: &impl Fn(&ratatui::buffer::Cell) -> bool,
) -> std::collections::BTreeSet<(u16, u16)> {
    let area = buffer.area;
    (0..area.height)
        .flat_map(|y| (0..area.width).map(move |x| (x, y)))
        .filter(|&cell| matches(&buffer[cell]))
        .collect()
}

fn remove_connected_region(cells: &mut std::collections::BTreeSet<(u16, u16)>, start: (u16, u16)) {
    let mut pending = vec![start];
    while let Some((x, y)) = pending.pop() {
        if cells.remove(&(x, y)) {
            pending.extend([
                (x.wrapping_sub(1), y),
                (x.wrapping_add(1), y),
                (x, y.wrapping_sub(1)),
                (x, y.wrapping_add(1)),
            ]);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::layout::Rect;

    fn reversed_rows(rows: &[(u16, std::ops::Range<u16>)]) -> Buffer {
        let mut buffer = Buffer::empty(Rect::new(0, 0, 10, 4));
        for (y, columns) in rows {
            for x in columns.clone() {
                buffer[(x, *y)].modifier = Modifier::REVERSED;
            }
        }
        buffer
    }

    fn reversed_regions(buffer: &Buffer) -> usize {
        style_region_count(buffer, |cell| cell.modifier.contains(Modifier::REVERSED))
    }

    #[test]
    fn a_multi_row_selected_card_is_one_selection_region() {
        let card = reversed_rows(&[(1, 0..8), (2, 0..5)]);
        assert_eq!(reversed_regions(&card), 1);
    }

    #[test]
    fn separate_selection_bands_still_count_separately() {
        let bands = reversed_rows(&[(0, 0..3), (0, 5..8), (2, 0..3)]);
        assert_eq!(reversed_regions(&bands), 3);
    }

    #[test]
    fn runtime_proof_atom_accepts_each_rendered_spelling() {
        for text in ["[●●●] s1", "[***] s1", "F-0001 C runtime verified"] {
            assert!(contains_contract_atom(text, "[●●●]"), "{text}");
        }
        assert!(!contains_contract_atom("F-0001 C static evidence", "[●●●]"));
    }
}
