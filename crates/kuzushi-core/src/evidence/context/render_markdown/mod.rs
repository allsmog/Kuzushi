use super::*;

mod evidence_graph;
mod registry_matches;
mod summary_sections;

pub(crate) fn render_markdown(
    narrative: Option<&StaticFindingNarrative>,
    registry: &[StaticRegistryMatch],
    nodes: &[StaticEvidenceNode],
    edges: &[StaticEvidenceEdge],
    proof_state: Option<StaticProofState>,
    impact: Option<crate::static_ranking::StaticImpactScore>,
) -> String {
    let mut out = String::with_capacity(2048);
    summary_sections::push_static_evidence_intro(&mut out);
    summary_sections::push_narrative_summary(&mut out, narrative);
    summary_sections::push_proof_state(&mut out, proof_state);
    summary_sections::push_impact_score(&mut out, impact);
    registry_matches::push_registry_matches(&mut out, registry);
    evidence_graph::push_evidence_graph(&mut out, nodes, edges);
    summary_sections::push_evidence_limits(&mut out, narrative);
    out
}
