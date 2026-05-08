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
    let narrowed_candidates =
        narrow_taint_iris_next_candidates_syntactically(&plan.scan_root, raw_candidates);
    // Drop candidates whose file path is obviously non-production code
    // (test/, tutorial/, fixtures/, etc.). Filtering at the candidate
    // level — not just at the linked-story level — keeps the agent
    // prompt's `candidates` block clean too, so the agent can't
    // speculate on tutorial/test paths even when the heuristic linker
    // produces zero stories. Operators who explicitly want to scan
    // non-production code can flip the catalog or pass a
    // `targetSubdir` constrained at a non-production path.
    let mut candidates: Vec<TaintIrisNextCandidate> = narrowed_candidates
        .into_iter()
        .filter(|candidate| !is_taint_iris_next_non_production_path(&candidate.file_path))
        .collect();
    let mut warnings = plan.backend.warnings.clone();

    // When the backend selector picked joern (CPG present + binary on PATH),
    // run a real `reachableByFlows` query and trust its verdict.
    // Operationally this means: empty Joern flows → empty linked_stories,
    // not a fallback to the heuristic same-file linker. The whole point of
    // selecting joern is replacing the proximity heuristic with real data
    // flow; if the CPG says no source reaches any sink, that *is* the
    // signal we want to surface to the agent.
    //
    // The heuristic linker is only used when joern itself can't run
    // (binary missing mid-run, query timed out, parse error) — in those
    // cases we surface a warning so the operator knows the result is
    // best-effort.
    let mut backend_path_count = 0usize;
    let linked_stories = if plan.backend.selected == "codeql" {
        match super::run_codeql_flows(plan) {
            Ok(Some(flows)) => {
                backend_path_count = flows.len();
                let mut codeql_candidates = super::codeql_flows_to_candidates(&flows);
                candidates.append(&mut codeql_candidates);
                if flows.is_empty() {
                    warnings.push(
                        "codeql analyze produced no security results; reporting empty linked stories rather than synthesising heuristic ones".to_string(),
                    );
                }
                super::codeql_flows_to_linked_stories(&flows)
            }
            Ok(None) => {
                warnings.push(
                    "codeql was selected but the launcher or DB disappeared between plan and run; using heuristic linker".to_string(),
                );
                build_taint_iris_next_linked_stories(&candidates)
            }
            Err(error) => {
                warnings.push(format!(
                    "codeql analyze failed ({error}); falling back to heuristic linker"
                ));
                build_taint_iris_next_linked_stories(&candidates)
            }
        }
    } else if plan.backend.selected == "joern" {
        match super::run_joern_flows(plan) {
            Ok(Some(flows)) => {
                backend_path_count = flows.len();
                let mut joern_candidates = super::joern_flows_to_candidates(&flows);
                candidates.append(&mut joern_candidates);
                if flows.is_empty() {
                    warnings.push(
                        "joern reachableByFlows found no source-to-sink paths; reporting empty linked stories rather than synthesising heuristic ones".to_string(),
                    );
                }
                super::joern_flows_to_linked_stories(&flows)
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
