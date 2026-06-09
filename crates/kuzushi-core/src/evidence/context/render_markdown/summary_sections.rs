use super::*;

pub(super) fn push_static_evidence_intro(out: &mut String) {
    out.push_str("## Pre-populated Static Evidence\n\n");
    out.push_str(
        "_Treat registry-tagged sources/sinks/sanitizers as authoritative starting points; \
         verify them in the source rather than re-discovering. Spend your tool budget on \
         flow analysis, not symbol lookup._\n\n",
    );
}

pub(super) fn push_narrative_summary(out: &mut String, narrative: Option<&StaticFindingNarrative>) {
    if let Some(narrative) = narrative {
        out.push_str("**Trigger path:** ");
        out.push_str(&narrative.static_trigger_path);
        out.push_str("\n\n**Potential impact:** ");
        out.push_str(&narrative.potential_impact);
        out.push_str("\n\n");
    }
}

pub(super) fn push_proof_state(out: &mut String, proof_state: Option<StaticProofState>) {
    if let Some(state) = proof_state {
        out.push_str("**Static proof state:** `");
        out.push_str(state.as_str());
        out.push_str("`\n\n");
    }
}

pub(super) fn push_impact_score(
    out: &mut String,
    impact: Option<crate::static_ranking::StaticImpactScore>,
) {
    if let Some(score) = impact {
        out.push_str(&format!("**Impact score:** {}", score.total));
        if !score.reasons.is_empty() {
            let preview: Vec<&str> = score.reasons.iter().take(3).map(String::as_str).collect();
            out.push_str(&format!(" ({})", preview.join(", ")));
        }
        out.push_str("\n\n");
    }
}

pub(super) fn push_evidence_limits(out: &mut String, narrative: Option<&StaticFindingNarrative>) {
    if let Some(narrative) = narrative {
        out.push_str("**Evidence limits:** ");
        out.push_str(&narrative.evidence_limits);
        out.push('\n');
    }
}
