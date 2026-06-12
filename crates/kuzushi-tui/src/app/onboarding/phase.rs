//! The four-phase engagement model the launch flow walks an operator
//! through, themed after the judo throw the tool is named for: establish the
//! grip (組 kumi-kata), break the balance (崩 kuzushi — the namesake), commit
//! the entry (作 tsukuri), finish (掛 kake).

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
    fn labels_lead_with_judo_term() {
        assert!(WorkflowPhase::Hunt.label().contains("KUZUSHI"));
        assert_eq!(WorkflowPhase::Map.position(), 1);
        assert_eq!(WorkflowPhase::Fix.position(), 4);
    }
}
