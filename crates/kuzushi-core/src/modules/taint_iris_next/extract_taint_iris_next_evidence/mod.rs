use super::*;

mod evidence_projection;
mod labeled_specs;
mod result_summary;
mod rg_engine;
mod structural_candidates;

pub(in crate::modules::taint_iris_next) use rg_engine::rg_available;

pub(in crate::modules) fn extract_taint_iris_next_evidence(
    plan: &TaintIrisNextPlan,
) -> Result<TaintIrisNextEvidenceResult> {
    let raw_candidates = structural_candidates::collect_structural_candidates(plan)?;
    // Syntactic narrowing: drop candidates whose match landed in a comment
    // or string literal. Languages without a tree-sitter grammar pass
    // through unchanged. This happens *after* the catalog language gate
    // so we never parse files for CWEs we'd reject anyway, and *before*
    // linked-story construction so noise candidates can't pair into
    // bogus source-to-sink stories.
    let mut candidates =
        narrow_taint_iris_next_candidates_syntactically(&plan.scan_root, raw_candidates);
    let mut warnings = plan.backend.warnings.clone();

    // When the backend selector picked joern (CPG present + binary on PATH),
    // run a real `reachableByFlows` query and replace the heuristic linker
    // with the resulting paths. The rg-derived candidates stay so the
    // catalog still has structural breadth; joern adds high-confidence
    // endpoints with `evidence_level: "path"` and a reaching-flow rationale.
    let mut backend_path_count = 0usize;
    let linked_stories = if plan.backend.selected == "joern" {
        match super::run_joern_flows(plan) {
            Ok(Some(flows)) => {
                backend_path_count = flows.len();
                let mut joern_candidates = super::joern_flows_to_candidates(&flows);
                candidates.append(&mut joern_candidates);
                let stories = super::joern_flows_to_linked_stories(&flows);
                if stories.is_empty() {
                    warnings.push(
                        "joern reachableByFlows produced no source-to-sink paths; falling back to heuristic linker for breadth".to_string(),
                    );
                    build_taint_iris_next_linked_stories(&candidates)
                } else {
                    stories
                }
            }
            Ok(None) => {
                warnings.push(
                    "joern was selected but the launcher or CPG disappeared between plan and run; using heuristic linker".to_string(),
                );
                build_taint_iris_next_linked_stories(&candidates)
            }
            Err(error) => {
                warnings.push(format!(
                    "joern dataflow query failed ({error}); falling back to heuristic linker"
                ));
                build_taint_iris_next_linked_stories(&candidates)
            }
        }
    } else {
        build_taint_iris_next_linked_stories(&candidates)
    };

    let linked_by_candidate = result_summary::linked_story_ids_by_candidate(&linked_stories);
    let mut evidence =
        evidence_projection::project_candidate_evidence(&candidates, &linked_by_candidate);
    cap_taint_iris_next_evidence(&mut evidence, plan.caps.max_evidence_per_cwe);

    let labeled_specs = labeled_specs::build_labeled_specs(plan, &candidates);
    let candidate_counts = count_taint_iris_next_candidates(&candidates);
    let labeled_spec_counts = result_summary::count_labeled_specs(&labeled_specs);
    let linked_story_count = linked_stories.len();
    let finding_count = linked_story_count;
    let candidate_count = evidence.len().saturating_sub(finding_count);

    Ok(TaintIrisNextEvidenceResult {
        backend: plan.backend.selected.clone(),
        tool: result_summary::selected_tool(plan),
        evidence,
        candidates,
        linked_stories,
        labeled_specs,
        query_count: plan.structural_queries.len(),
        candidate_counts,
        labeled_spec_counts,
        linked_story_count,
        backend_path_count,
        structural_engine: plan.backend.structural_tool.clone(),
        triage_summary: json!({
            "finding": finding_count,
            "candidate": candidate_count,
            "rejected": 0,
        }),
        outcome: result_summary::outcome(linked_story_count, candidate_count).to_string(),
        warnings,
        artifacts: json!({
            "codeqlLanguage": Value::Null,
            "codeqlQueryPath": Value::Null,
            "codeqlCompileStatus": "not-run",
        }),
    })
}
