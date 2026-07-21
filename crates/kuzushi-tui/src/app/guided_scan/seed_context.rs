use super::*;
use crate::ui_view_models::{
    recommendation_model, threat_model_doc, RecommendationRow, NO_REASON_RECORDED,
};
use std::collections::{BTreeMap, BTreeSet};

/// Threat-model and recommender evidence behind the Scan configure card, so
/// the module plan reads as "recommended because …" instead of a bare list
/// the operator has to trust blind.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ScanSeedContext {
    pub(super) provenance: String,
    reasons: BTreeMap<String, String>,
    recommended: BTreeSet<String>,
}

impl ScanSeedContext {
    pub(super) fn reason_for(&self, tool: &str) -> Option<&str> {
        self.reasons.get(tool).map(String::as_str)
    }

    pub(super) fn recommends(&self, tool: &str) -> bool {
        self.recommended.contains(tool)
    }
}

impl ShellApp {
    pub(super) fn scan_seed_context(&self) -> ScanSeedContext {
        let (reasons, recommended) = recommendation_seeds(&recommendation_model(self).rows);
        ScanSeedContext {
            provenance: provenance_line(
                threat_counts(threat_model_doc(self).as_ref()),
                reasons.is_empty() && recommended.is_empty(),
            ),
            reasons,
            recommended,
        }
    }
}

fn provenance_line(counts: Option<(usize, usize)>, without_recommendations: bool) -> String {
    match counts {
        Some((threats, boundaries)) => format!(
            "Seeded by the threat model ({threats} threat(s) · {boundaries} trust boundar{}) and workspace signals.",
            if boundaries == 1 { "y" } else { "ies" }
        ),
        None if without_recommendations => {
            "No threat model or recommendation evidence yet — generic engine defaults. Run Map to seed this plan."
                .to_string()
        }
        None => "Seeded by workspace signals only — no threat model yet. Run Map to sharpen this plan."
            .to_string(),
    }
}

/// Threat/boundary counts only when the persisted model carries a concrete
/// DFD; a scope-placeholder-only document must not claim to seed anything.
fn threat_counts(doc: Option<&serde_json::Value>) -> Option<(usize, usize)> {
    let doc = doc?;
    let concrete = kuzushi_core::workflow_attempts::threat_model_has_concrete_dfd(doc)
        && !kuzushi_core::workflow_attempts::threat_model_is_scope_placeholder_only(doc);
    concrete.then(|| {
        (
            array_len(doc.get("threats")),
            array_len(doc.pointer("/dfd/trustBoundaries")),
        )
    })
}

fn array_len(value: Option<&serde_json::Value>) -> usize {
    value
        .and_then(serde_json::Value::as_array)
        .map(Vec::len)
        .unwrap_or(0)
}

/// Join the deterministic recommender rows into per-tool rationales and a
/// recommended set. Artifact-error pseudo rows carry a file name instead of a
/// `<module>:<verb>` tool name and are skipped.
fn recommendation_seeds(
    rows: &[RecommendationRow],
) -> (BTreeMap<String, String>, BTreeSet<String>) {
    let mut reasons = BTreeMap::new();
    let mut recommended = BTreeSet::new();
    for row in rows {
        let [priority, tool, _, _, reason] = &row.cells;
        if !tool.contains(':') {
            continue;
        }
        if !reason.trim().is_empty() && reason != NO_REASON_RECORDED {
            reasons.insert(tool.clone(), reason.clone());
        }
        if priority != "○ low" {
            recommended.insert(tool.clone());
        }
    }
    (reasons, recommended)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(priority: &str, tool: &str, reason: &str) -> RecommendationRow {
        RecommendationRow {
            cells: [
                priority.to_string(),
                tool.to_string(),
                "no".to_string(),
                "-".to_string(),
                reason.to_string(),
            ],
        }
    }

    #[test]
    fn recommendation_seeds_join_reasons_and_flag_non_low_priorities() {
        let (reasons, recommended) = recommendation_seeds(&[
            row(
                "⚠ high",
                "semgrep:scan",
                "Falcon routes match semgrep coverage.",
            ),
            row("○ low", "context:build", NO_REASON_RECORDED),
            row(
                "⚠ high",
                "recommendations.json",
                "Malformed JSON; regenerate.",
            ),
        ]);

        assert_eq!(
            reasons.get("semgrep:scan").map(String::as_str),
            Some("Falcon routes match semgrep coverage.")
        );
        assert!(!reasons.contains_key("context:build"));
        assert!(recommended.contains("semgrep:scan"));
        assert!(!recommended.contains("context:build"));
        assert!(!recommended.contains("recommendations.json"));
    }

    #[test]
    fn provenance_line_states_threat_model_seeding_with_counts() {
        let doc = json!({
            "dfd": {
                "nodes": [
                    {"id": "a", "name": "api", "trustZone": "app", "type": "process"},
                    {"id": "b", "name": "db", "trustZone": "data", "type": "data-store"}
                ],
                "flows": [{"id": "f", "sourceId": "a", "targetId": "b"}],
                "trustBoundaries": [{"id": "edge"}]
            },
            "threats": [{"id": "T-1"}, {"id": "T-2"}]
        });

        let line = provenance_line(threat_counts(Some(&doc)), true);

        assert_eq!(
            line,
            "Seeded by the threat model (2 threat(s) · 1 trust boundary) and workspace signals."
        );
    }

    #[test]
    fn scope_placeholder_model_does_not_claim_seeding() {
        let doc = json!({
            "dfd": {
                "nodes": [{
                    "id": "n1",
                    "name": "fixture repository scope",
                    "trustZone": "analysis-scope",
                    "type": "process"
                }],
                "flows": []
            },
            "threats": []
        });

        assert_eq!(threat_counts(Some(&doc)), None);
    }

    #[test]
    fn provenance_line_degrades_honestly_without_any_evidence() {
        let generic = provenance_line(None, true);
        let signals_only = provenance_line(None, false);

        assert!(generic.contains("generic engine defaults"));
        assert!(generic.contains("Run Map"));
        assert!(signals_only.contains("workspace signals only"));
    }
}
