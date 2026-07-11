//! The four-phase engagement model the launch flow walks an operator
//! through, themed after the judo throw the tool is named for: establish the
//! grip (組 kumi-kata), break the balance (崩 kuzushi — the namesake), commit
//! the entry (作 tsukuri), finish (掛 kake).
//!
//! This enum is the shared, pure phase concept for the whole workspace. It
//! lives in `kuzushi-core` so the tool-dispatch boundary (and the autonomy
//! gate) can reason about "how far along the spine a tool sits" without
//! depending on the TUI crate. The TUI imports and re-exports this type
//! directly from `kuzushi-core`.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum WorkflowPhase {
    /// 組 KUMI-KATA — establish the grip: gather context & build analysis artifacts.
    Map,
    /// 崩 KUZUSHI — break the target's balance: hunt for vulnerabilities.
    Hunt,
    /// 作 TSUKURI — commit the entry: triage & verify findings.
    Confirm,
    /// 掛 KAKE — finish the throw: patch & report.
    Fix,
}

impl WorkflowPhase {
    /// Canonical phase order the walker advances through.
    pub const ORDER: &'static [WorkflowPhase] = &[
        WorkflowPhase::Map,
        WorkflowPhase::Hunt,
        WorkflowPhase::Confirm,
        WorkflowPhase::Fix,
    ];

    /// The next phase in the engagement, or `None` after 掛 KAKE.
    pub fn next(self) -> Option<WorkflowPhase> {
        match self {
            WorkflowPhase::Map => Some(WorkflowPhase::Hunt),
            WorkflowPhase::Hunt => Some(WorkflowPhase::Confirm),
            WorkflowPhase::Confirm => Some(WorkflowPhase::Fix),
            WorkflowPhase::Fix => None,
        }
    }

    /// The previous phase in the engagement, or `None` before 組 KUMI-KATA.
    pub fn previous(self) -> Option<WorkflowPhase> {
        match self {
            WorkflowPhase::Map => None,
            WorkflowPhase::Hunt => Some(WorkflowPhase::Map),
            WorkflowPhase::Confirm => Some(WorkflowPhase::Hunt),
            WorkflowPhase::Fix => Some(WorkflowPhase::Confirm),
        }
    }

    pub fn parse(raw: &str) -> Option<WorkflowPhase> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "map" | "1" | "kumi" | "kumi-kata" | "組" => Some(WorkflowPhase::Map),
            "hunt" | "2" | "kuzushi" | "崩" => Some(WorkflowPhase::Hunt),
            "confirm" | "3" | "tsukuri" | "作" => Some(WorkflowPhase::Confirm),
            "fix" | "4" | "kake" | "掛" => Some(WorkflowPhase::Fix),
            _ => None,
        }
    }

    /// Judo-primary header label (glyph · romaji · plain word).
    pub fn label(self) -> &'static str {
        match self {
            WorkflowPhase::Map => "組 KUMI-KATA · map",
            WorkflowPhase::Hunt => "崩 KUZUSHI · hunt",
            WorkflowPhase::Confirm => "作 TSUKURI · confirm",
            WorkflowPhase::Fix => "掛 KAKE · fix",
        }
    }

    /// Judo glyph alone — for compact chrome (phase rail, footer chip).
    pub fn kanji(self) -> &'static str {
        match self {
            WorkflowPhase::Map => "組",
            WorkflowPhase::Hunt => "崩",
            WorkflowPhase::Confirm => "作",
            WorkflowPhase::Fix => "掛",
        }
    }

    /// Plain one-word name — for compact chrome (phase rail, footer chip).
    pub fn word(self) -> &'static str {
        match self {
            WorkflowPhase::Map => "map",
            WorkflowPhase::Hunt => "hunt",
            WorkflowPhase::Confirm => "confirm",
            WorkflowPhase::Fix => "fix",
        }
    }

    /// One-line statement of what the phase is for.
    pub fn intent(self) -> &'static str {
        match self {
            WorkflowPhase::Map => {
                "establish the grip — gather context and build analysis artifacts"
            }
            WorkflowPhase::Hunt => "break the target's balance — hunt for vulnerabilities",
            WorkflowPhase::Confirm => "commit the entry — triage and verify findings",
            WorkflowPhase::Fix => "finish the throw — patch and report",
        }
    }

    /// 1-based position used in "phase 2 of 4"-style copy.
    pub fn position(self) -> usize {
        WorkflowPhase::ORDER
            .iter()
            .position(|phase| *phase == self)
            .map(|index| index + 1)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn order_is_map_hunt_confirm_fix() {
        assert_eq!(
            WorkflowPhase::ORDER,
            &[
                WorkflowPhase::Map,
                WorkflowPhase::Hunt,
                WorkflowPhase::Confirm,
                WorkflowPhase::Fix
            ]
        );
    }

    #[test]
    fn next_walks_to_end() {
        assert_eq!(WorkflowPhase::Map.next(), Some(WorkflowPhase::Hunt));
        assert_eq!(WorkflowPhase::Confirm.next(), Some(WorkflowPhase::Fix));
        assert_eq!(WorkflowPhase::Fix.next(), None);
    }

    #[test]
    fn previous_walks_to_start() {
        assert_eq!(WorkflowPhase::Map.previous(), None);
        assert_eq!(WorkflowPhase::Hunt.previous(), Some(WorkflowPhase::Map));
        assert_eq!(WorkflowPhase::Fix.previous(), Some(WorkflowPhase::Confirm));
    }

    #[test]
    fn labels_lead_with_judo_term() {
        assert!(WorkflowPhase::Hunt.label().contains("KUZUSHI"));
        assert_eq!(WorkflowPhase::Map.position(), 1);
        assert_eq!(WorkflowPhase::Fix.position(), 4);
    }

    #[test]
    fn parse_accepts_named_and_numbered_phases() {
        assert_eq!(WorkflowPhase::parse("map"), Some(WorkflowPhase::Map));
        assert_eq!(WorkflowPhase::parse("2"), Some(WorkflowPhase::Hunt));
        assert_eq!(
            WorkflowPhase::parse("confirm"),
            Some(WorkflowPhase::Confirm)
        );
        assert_eq!(WorkflowPhase::parse("掛"), Some(WorkflowPhase::Fix));
        assert_eq!(WorkflowPhase::parse("later"), None);
    }

    #[test]
    fn ordering_matches_spine_progression() {
        assert!(WorkflowPhase::Map < WorkflowPhase::Hunt);
        assert!(WorkflowPhase::Hunt < WorkflowPhase::Confirm);
        assert!(WorkflowPhase::Confirm < WorkflowPhase::Fix);
    }
}
