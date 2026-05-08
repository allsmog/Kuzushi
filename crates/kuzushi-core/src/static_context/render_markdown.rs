use super::prelude::*;
use super::*;

pub(crate) fn render_markdown(
    narrative: Option<&StaticFindingNarrative>,
    registry: &[StaticRegistryMatch],
    nodes: &[StaticEvidenceNode],
    edges: &[StaticEvidenceEdge],
    proof_state: Option<StaticProofState>,
    impact: Option<crate::static_ranking::StaticImpactScore>,
) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("## Pre-populated Static Evidence\n\n");
    out.push_str(
        "_Treat registry-tagged sources/sinks/sanitizers as authoritative starting points; \
         verify them in the source rather than re-discovering. Spend your tool budget on \
         flow analysis, not symbol lookup._\n\n",
    );

    if let Some(n) = narrative {
        out.push_str("**Trigger path:** ");
        out.push_str(&n.static_trigger_path);
        out.push_str("\n\n**Potential impact:** ");
        out.push_str(&n.potential_impact);
        out.push_str("\n\n");
    }

    if let Some(state) = proof_state {
        out.push_str("**Static proof state:** `");
        out.push_str(state.as_str());
        out.push_str("`\n\n");
    }

    if let Some(score) = impact {
        out.push_str(&format!("**Impact score:** {}", score.total));
        if !score.reasons.is_empty() {
            let preview: Vec<&str> = score.reasons.iter().take(3).map(String::as_str).collect();
            out.push_str(&format!(" ({})", preview.join(", ")));
        }
        out.push_str("\n\n");
    }

    let by_kind = group_registry_by_kind(registry);
    let kind_label_pairs = [
        (StaticRegistryKind::Source, "**Known sources**"),
        (StaticRegistryKind::Sink, "**Known sinks**"),
        (StaticRegistryKind::Sanitizer, "**Known sanitizers**"),
        (StaticRegistryKind::Guard, "**Known guards**"),
    ];
    for (kind, label) in kind_label_pairs {
        if let Some(matches) = by_kind.get(&kind) {
            if matches.is_empty() {
                continue;
            }
            out.push_str(label);
            out.push_str(" (registry):\n");
            for m in matches.iter().take(8) {
                out.push_str("- `");
                out.push_str(&m.entry.pattern);
                out.push_str("`");
                if !m.entry.cwe.is_empty() {
                    out.push_str(" (");
                    out.push_str(&m.entry.cwe.join(", "));
                    out.push_str(")");
                }
                if !m.entry.rationale.is_empty() {
                    out.push_str(" - ");
                    out.push_str(&m.entry.rationale);
                }
                out.push_str("\n");
            }
            out.push_str("\n");
        }
    }

    if !nodes.is_empty() {
        out.push_str(&format!(
            "**Evidence graph slice** ({} nodes, +/-{} lines of finding):\n",
            nodes.len(),
            SUBGRAPH_LINE_WINDOW
        ));
        for node in nodes {
            out.push_str("- ");
            out.push_str(node.kind.as_str());
            if let (Some(path), Some(line)) = (&node.source_path, node.start_line) {
                out.push_str(&format!(" @ `{}:{}`", path, line));
            }
            if !node.body.is_empty() {
                let trimmed = node.body.lines().next().unwrap_or("").trim();
                if !trimmed.is_empty() {
                    out.push_str(" body: `");
                    out.push_str(&truncate_for_prompt(trimmed, 80));
                    out.push_str("`");
                }
            }
            out.push_str("\n");
        }
        if !edges.is_empty() {
            out.push_str("\n");
            for edge in edges {
                out.push_str(&format!(
                    "- Edge: `{}` --{}--> `{}`\n",
                    edge.from_node_id,
                    edge.kind.as_str(),
                    edge.to_node_id
                ));
            }
        }
        out.push_str("\n");
    }

    if let Some(n) = narrative {
        out.push_str("**Evidence limits:** ");
        out.push_str(&n.evidence_limits);
        out.push_str("\n");
    }

    out
}
