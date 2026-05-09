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
    // Fold the per-target source/sink discovery sweep into the
    // candidate list so the agent investigates real primitives
    // (`dlopen`, `load_external_function`, `SetUserId`,
    // `PG_FUNCTION_INFO_V1` entry points, …) instead of only whatever
    // the static catalog happened to seed via rg matches. Without this
    // step the discovery output is informational only — it shows up
    // in the prompt's "## Discovered Signals" section but the agent
    // doesn't pivot to it because there are no candidate rows to
    // anchor on.
    let discovered_candidates =
        candidates_from_discovered_signals(&plan.discovered_signals, &plan.cwe_focus);
    candidates.extend(discovered_candidates);
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

/// Caps for synthesised discovery-derived candidates so a postgres
/// scan with 1041 PG_FUNCTION_INFO_V1 entry points doesn't drown the
/// prompt or the structural-pass downstream consumers. The discovery
/// artefact at `.kuzushi/discovered-signals.json` keeps the full set
/// for offline review.
const DISCOVERY_MAX_SINK_CANDIDATES: usize = 80;
const DISCOVERY_MAX_ENTRY_POINT_CANDIDATES: usize = 40;

/// Project per-target discovery output (sinks + entry points) into
/// `TaintIrisNextCandidate` rows so the rest of the pipeline (linked
/// stories, evidence projection, agent prompt's `## Candidates` block)
/// can use them as anchors. Entry points map to the `source` role,
/// sinks to the `sink` role; both are tagged with `source: "discovery"`
/// so downstream consumers can tell them apart from rg / joern /
/// codeql derived rows.
///
/// Honors the operator's `cweFocus` filter so a privesc/RCE-scoped
/// hunt doesn't get its prompt diluted with CWE-862 entry points it
/// already filtered the catalog against.
fn candidates_from_discovered_signals(
    signals: &DiscoveredSignals,
    cwe_focus: &[String],
) -> Vec<TaintIrisNextCandidate> {
    if signals.sinks.is_empty() && signals.entry_points.is_empty() {
        return Vec::new();
    }
    let allow: std::collections::BTreeSet<String> = cwe_focus
        .iter()
        .map(|cwe| cwe.to_ascii_uppercase())
        .collect();
    let mut out: Vec<TaintIrisNextCandidate> = Vec::new();
    for (signal, role, kind, max_per_role) in signals
        .sinks
        .iter()
        .map(|s| (s, "sink", "call", DISCOVERY_MAX_SINK_CANDIDATES))
        .chain(
            signals.entry_points.iter().map(|e| {
                (e, "source", "entry-point", DISCOVERY_MAX_ENTRY_POINT_CANDIDATES)
            }),
        )
    {
        if !allow.is_empty() && !allow.contains(&signal.cwe.to_ascii_uppercase()) {
            continue;
        }
        let same_role_count = out.iter().filter(|c| c.role == role).count();
        if same_role_count >= max_per_role {
            continue;
        }
        out.push(TaintIrisNextCandidate {
            id: format!(
                "{}:{role}:discovered:{}:{}:{}",
                signal.cwe, signal.file, signal.line, signal.name
            ),
            cwe: signal.cwe.clone(),
            taint_class: taint_class_for_discovered_cwe(&signal.cwe).to_string(),
            track: "taint".to_string(),
            role: role.to_string(),
            kind: kind.to_string(),
            pattern: signal.name.clone(),
            file_path: signal.file.clone(),
            line: signal.line,
            snippet: format!("[discovery:{}] {}", signal.marker, signal.name),
            language: signal.language.clone(),
            confidence: "medium".to_string(),
            catalog_signal: format!("{role}: {} ({})", signal.name, signal.marker),
            source: "discovery".to_string(),
        });
    }
    out
}

/// Map the small set of CWEs the discovery sweep emits to the same
/// `taintClass` strings the static catalog uses. Discovery only fires
/// on CWE-78/77/94/250/269/426/862 so we don't need a full table —
/// keep it explicit so a typo in the marker table fails loud here
/// instead of producing a candidate with a blank taintClass.
fn taint_class_for_discovered_cwe(cwe: &str) -> &'static str {
    match cwe {
        "CWE-78" | "CWE-77" => "command-injection",
        "CWE-94" => "code-injection",
        "CWE-426" => "search-path",
        "CWE-269" | "CWE-250" => "privesc",
        "CWE-732" => "permission",
        "CWE-862" => "missing-authorization",
        _ => "discovery",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal(name: &str, cwe: &str, kind: &str, file: &str, line: u32) -> DiscoveredSignal {
        DiscoveredSignal {
            name: name.to_string(),
            cwe: cwe.to_string(),
            kind: kind.to_string(),
            language: "c".to_string(),
            marker: "test".to_string(),
            file: file.to_string(),
            line,
        }
    }

    #[test]
    fn synthesises_one_candidate_per_discovered_sink_and_entrypoint() {
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: Vec::new(),
            sinks: vec![
                signal("dlopen", "CWE-94", "sink", "src/backend/utils/fmgr/dfmgr.c", 244),
                signal("system", "CWE-78", "sink", "src/backend/access/transam/xlogarchive.c", 168),
            ],
            entry_points: vec![signal(
                "pg_read_server_files",
                "CWE-862",
                "entrypoint",
                "src/backend/utils/adt/genfile.c",
                100,
            )],
            discoverers: vec!["test".to_string()],
        };
        // No cwe_focus → all signals project.
        let candidates = candidates_from_discovered_signals(&signals, &[]);
        assert_eq!(candidates.len(), 3);
        let by_role: std::collections::BTreeMap<&str, usize> = candidates
            .iter()
            .map(|c| c.role.as_str())
            .fold(std::collections::BTreeMap::new(), |mut acc, role| {
                *acc.entry(role).or_default() += 1;
                acc
            });
        assert_eq!(by_role.get("sink"), Some(&2));
        assert_eq!(by_role.get("source"), Some(&1));
        // Tag must be discovery so downstream consumers can distinguish
        // from rg / joern / codeql derived candidates.
        assert!(candidates.iter().all(|c| c.source == "discovery"));
        // taintClass must be the catalog-aligned label, not "discovery".
        let dlopen = candidates.iter().find(|c| c.pattern == "dlopen").unwrap();
        assert_eq!(dlopen.taint_class, "code-injection");
        assert_eq!(dlopen.cwe, "CWE-94");
    }

    #[test]
    fn cwe_focus_filters_discovered_candidates() {
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: Vec::new(),
            sinks: vec![
                signal("dlopen", "CWE-94", "sink", "f.c", 1),
                signal("popen", "CWE-78", "sink", "f.c", 2),
                signal("RestrictSearchPath", "CWE-426", "sink", "f.c", 3),
            ],
            entry_points: vec![],
            discoverers: vec!["test".to_string()],
        };
        let cwe_focus = vec!["CWE-78".to_string(), "CWE-94".to_string()];
        let candidates = candidates_from_discovered_signals(&signals, &cwe_focus);
        assert_eq!(candidates.len(), 2, "CWE-426 must be excluded by focus");
        let cwes: std::collections::BTreeSet<&str> =
            candidates.iter().map(|c| c.cwe.as_str()).collect();
        assert!(cwes.contains("CWE-78"));
        assert!(cwes.contains("CWE-94"));
        assert!(!cwes.contains("CWE-426"));
    }

    #[test]
    fn caps_per_role_keep_prompt_compact() {
        // 200 dlopen sinks would otherwise drown the prompt; the cap
        // keeps it bounded.
        let mut sinks = Vec::new();
        for line in 0..200 {
            sinks.push(signal("dlopen", "CWE-94", "sink", "f.c", line as u32));
        }
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: Vec::new(),
            sinks,
            entry_points: Vec::new(),
            discoverers: vec!["test".to_string()],
        };
        let candidates = candidates_from_discovered_signals(&signals, &[]);
        assert_eq!(candidates.len(), DISCOVERY_MAX_SINK_CANDIDATES);
    }
}
