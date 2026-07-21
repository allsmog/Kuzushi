//! The five durable phases of a Kuzushi security engagement.
//!
//! Page selection is presentation state. This enum models the ordered domain
//! spine used by planning and authorization: map the target, scan for candidate
//! signals, review those candidates, prove the actionable findings, then fix
//! them. Keeping the concept in `kuzushi-core` lets every execution mode use
//! the same policy without depending on the interactive shell.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WorkflowPhase {
    /// Build target context, scope, inventory, and analysis artifacts.
    Map,
    /// Produce candidate findings and other security signals.
    #[serde(alias = "hunt")]
    Scan,
    /// Triage, classify, and record decisions about candidate findings.
    Review,
    /// Produce empirical verification evidence for actionable findings.
    #[serde(alias = "confirm")]
    Prove,
    /// Draft, apply, re-verify, and report remediation.
    Fix,
}

impl WorkflowPhase {
    /// Canonical phase order the engagement walks through.
    pub const ORDER: &'static [WorkflowPhase] = &[
        WorkflowPhase::Map,
        WorkflowPhase::Scan,
        WorkflowPhase::Review,
        WorkflowPhase::Prove,
        WorkflowPhase::Fix,
    ];

    pub fn next(self) -> Option<WorkflowPhase> {
        match self {
            WorkflowPhase::Map => Some(WorkflowPhase::Scan),
            WorkflowPhase::Scan => Some(WorkflowPhase::Review),
            WorkflowPhase::Review => Some(WorkflowPhase::Prove),
            WorkflowPhase::Prove => Some(WorkflowPhase::Fix),
            WorkflowPhase::Fix => None,
        }
    }

    pub fn previous(self) -> Option<WorkflowPhase> {
        match self {
            WorkflowPhase::Map => None,
            WorkflowPhase::Scan => Some(WorkflowPhase::Map),
            WorkflowPhase::Review => Some(WorkflowPhase::Scan),
            WorkflowPhase::Prove => Some(WorkflowPhase::Review),
            WorkflowPhase::Fix => Some(WorkflowPhase::Prove),
        }
    }

    /// Parse a named phase. `hunt` and `confirm` remain compatibility aliases;
    /// numeric phase inputs are intentionally rejected because five phases
    /// changed their historical meaning.
    pub fn parse(raw: &str) -> Option<WorkflowPhase> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "map" | "kumi" | "kumi-kata" | "組" => Some(WorkflowPhase::Map),
            "scan" | "hunt" | "kuzushi" | "崩" => Some(WorkflowPhase::Scan),
            "review" => Some(WorkflowPhase::Review),
            "prove" | "confirm" | "verify" | "tsukuri" | "作" => Some(WorkflowPhase::Prove),
            "fix" | "kake" | "掛" => Some(WorkflowPhase::Fix),
            _ => None,
        }
    }

    /// Title-case operator word: the primary way a phase is named in chrome.
    pub fn title(self) -> &'static str {
        match self {
            WorkflowPhase::Map => "Map",
            WorkflowPhase::Scan => "Scan",
            WorkflowPhase::Review => "Review",
            WorkflowPhase::Prove => "Prove",
            WorkflowPhase::Fix => "Fix",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            WorkflowPhase::Map => "MAP",
            WorkflowPhase::Scan => "SCAN",
            WorkflowPhase::Review => "REVIEW",
            WorkflowPhase::Prove => "PROVE",
            WorkflowPhase::Fix => "FIX",
        }
    }

    /// Stable compact glyph. The word remains the primary accessible label.
    pub fn kanji(self) -> &'static str {
        match self {
            WorkflowPhase::Map => "組",
            WorkflowPhase::Scan => "崩",
            WorkflowPhase::Review => "査",
            WorkflowPhase::Prove => "作",
            WorkflowPhase::Fix => "掛",
        }
    }

    pub fn word(self) -> &'static str {
        match self {
            WorkflowPhase::Map => "map",
            WorkflowPhase::Scan => "scan",
            WorkflowPhase::Review => "review",
            WorkflowPhase::Prove => "prove",
            WorkflowPhase::Fix => "fix",
        }
    }

    pub fn intent(self) -> &'static str {
        match self {
            WorkflowPhase::Map => "gather context and build analysis artifacts",
            WorkflowPhase::Scan => "find candidate vulnerabilities and security signals",
            WorkflowPhase::Review => "triage, classify, and decide candidate findings",
            WorkflowPhase::Prove => "verify actionable findings with empirical evidence",
            WorkflowPhase::Fix => "patch, re-verify, and report",
        }
    }

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
    fn order_is_map_scan_review_prove_fix() {
        assert_eq!(
            WorkflowPhase::ORDER,
            &[
                WorkflowPhase::Map,
                WorkflowPhase::Scan,
                WorkflowPhase::Review,
                WorkflowPhase::Prove,
                WorkflowPhase::Fix,
            ]
        );
    }

    #[test]
    fn next_and_previous_walk_the_five_phase_spine() {
        assert_eq!(WorkflowPhase::Map.next(), Some(WorkflowPhase::Scan));
        assert_eq!(WorkflowPhase::Scan.next(), Some(WorkflowPhase::Review));
        assert_eq!(WorkflowPhase::Review.next(), Some(WorkflowPhase::Prove));
        assert_eq!(WorkflowPhase::Prove.next(), Some(WorkflowPhase::Fix));
        assert_eq!(WorkflowPhase::Fix.next(), None);
        assert_eq!(WorkflowPhase::Map.previous(), None);
        assert_eq!(WorkflowPhase::Fix.previous(), Some(WorkflowPhase::Prove));
    }

    #[test]
    fn parse_accepts_names_and_legacy_aliases_but_rejects_numbers() {
        assert_eq!(WorkflowPhase::parse("map"), Some(WorkflowPhase::Map));
        assert_eq!(WorkflowPhase::parse("hunt"), Some(WorkflowPhase::Scan));
        assert_eq!(WorkflowPhase::parse("review"), Some(WorkflowPhase::Review));
        assert_eq!(WorkflowPhase::parse("confirm"), Some(WorkflowPhase::Prove));
        assert_eq!(WorkflowPhase::parse("fix"), Some(WorkflowPhase::Fix));
        assert_eq!(WorkflowPhase::parse("2"), None);
    }

    #[test]
    fn ordering_matches_spine_progression() {
        assert!(WorkflowPhase::Map < WorkflowPhase::Scan);
        assert!(WorkflowPhase::Scan < WorkflowPhase::Review);
        assert!(WorkflowPhase::Review < WorkflowPhase::Prove);
        assert!(WorkflowPhase::Prove < WorkflowPhase::Fix);
        assert_eq!(WorkflowPhase::Fix.position(), 5);
    }

    #[test]
    fn serde_accepts_legacy_aliases_and_emits_canonical_tokens() {
        assert_eq!(
            serde_json::from_str::<WorkflowPhase>("\"hunt\"").unwrap(),
            WorkflowPhase::Scan
        );
        assert_eq!(
            serde_json::from_str::<WorkflowPhase>("\"confirm\"").unwrap(),
            WorkflowPhase::Prove
        );
        assert_eq!(
            serde_json::to_string(&WorkflowPhase::Review).unwrap(),
            "\"review\""
        );
        assert_eq!(
            serde_json::to_string(&WorkflowPhase::Prove).unwrap(),
            "\"prove\""
        );
    }
}
