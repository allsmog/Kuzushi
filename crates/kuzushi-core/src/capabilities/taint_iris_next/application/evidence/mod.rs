use super::*;

mod evidence_projection;
mod labeled_specs;
mod result_summary;
mod rg_engine;
mod structural_candidates;

pub(crate) use rg_engine::rg_available;

pub(crate) fn extract_taint_iris_next_evidence(
    plan: &TaintIrisNextPlan,
) -> Result<TaintIrisNextEvidenceResult> {
    let mut candidates = collect_taint_iris_next_candidates(plan)?;
    let mut warnings = plan.backend.warnings.clone();
    let primary = primary_backend_evidence(plan, &mut candidates, &mut warnings);
    let mut linked_stories = primary.linked_stories;
    let mut backend_path_count = primary.backend_path_count;
    corroborate_with_codeql(
        plan,
        &mut candidates,
        &mut linked_stories,
        &mut backend_path_count,
        &mut warnings,
    );

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

fn collect_taint_iris_next_candidates(
    plan: &TaintIrisNextPlan,
) -> Result<Vec<TaintIrisNextCandidate>> {
    let raw_candidates = structural_candidates::collect_structural_candidates(plan)?;
    // Fold the per-target source/sink discovery sweep into the raw
    // candidate stream BEFORE syntactic narrowing so discovery's
    // marker-regex matches go through the same comment/string-literal
    // filter as rg-derived candidates. Without this, comment hits like
    // `* random calls to C library routines like system(3);` (in
    // postgres `fd.c:17`) sneak through the discovery sweep as bogus
    // CWE-78 sinks and the cross-file linker happily pairs them into
    // 605 false-positive linked stories.
    let discovered_candidates =
        candidates_from_discovered_signals(&plan.discovered_signals, &plan.cwe_focus);
    let mut combined_raw = raw_candidates;
    combined_raw.extend(discovered_candidates);
    // E1: deterministic tree-sitter detector for identifier-position
    // SQL injection (the dblink_open/close/fetch finding shape).
    // Runs in <10s on a 1600-file tree, no LLM cost. Feeds candidates
    // marked `source: "ts.identifier-injection"` at confidence: high
    // so Thread D's call-site audit reaches them with the right
    // priority. Bounded by the same file-walker budget the discovery
    // sweep uses to stay below the structural-pass cap.
    let detector_candidates = run_identifier_injection_detector_for_plan(plan);
    combined_raw.extend(detector_candidates);
    // Syntactic narrowing: drop candidates whose match landed in a comment
    // or string literal. Languages without a tree-sitter grammar pass
    // through unchanged. This happens *after* the catalog language gate
    // so we never parse files for CWEs we'd reject anyway, and *before*
    // linked-story construction so noise candidates can't pair into
    // bogus source-to-sink stories.
    let narrowed_candidates =
        narrow_taint_iris_next_candidates_syntactically(&plan.scan_root, combined_raw);
    // Drop candidates whose file path is obviously non-production code
    // (test/, tutorial/, fixtures/, etc.). Filtering at the candidate
    // level — not just at the linked-story level — keeps the agent
    // prompt's `candidates` block clean too, so the agent can't
    // speculate on tutorial/test paths even when the heuristic linker
    // produces zero stories. Operators who explicitly want to scan
    // non-production code can flip the catalog or pass a
    // `targetSubdir` constrained at a non-production path.
    Ok(narrowed_candidates
        .into_iter()
        .filter(|candidate| !is_taint_iris_next_non_production_path(&candidate.file_path))
        .collect())
}

struct BackendEvidence {
    linked_stories: Vec<TaintIrisNextLinkedStory>,
    backend_path_count: usize,
}

fn primary_backend_evidence(
    plan: &TaintIrisNextPlan,
    candidates: &mut Vec<TaintIrisNextCandidate>,
    warnings: &mut Vec<String>,
) -> BackendEvidence {
    match plan.backend.selected.as_str() {
        "codeql" => codeql_backend_evidence(plan, candidates, warnings),
        "joern" => joern_backend_evidence(plan, candidates, warnings),
        _ => heuristic_backend_evidence(plan, candidates),
    }
}

fn codeql_backend_evidence(
    plan: &TaintIrisNextPlan,
    candidates: &mut Vec<TaintIrisNextCandidate>,
    warnings: &mut Vec<String>,
) -> BackendEvidence {
    let flows = match super::run_codeql_flows(plan) {
        Ok(flows) => flows,
        Err(error) => return codeql_error_fallback(plan, candidates, warnings, error),
    };
    let Some(flows) = flows else {
        return backend_fallback_evidence(
            plan,
            candidates,
            warnings,
            "codeql was selected but the launcher or DB disappeared between plan and run; using heuristic linker",
        );
    };
    codeql_flow_evidence(flows, candidates, warnings)
}

fn codeql_error_fallback(
    plan: &TaintIrisNextPlan,
    candidates: &[TaintIrisNextCandidate],
    warnings: &mut Vec<String>,
    error: anyhow::Error,
) -> BackendEvidence {
    let warning = format!("codeql analyze failed ({error}); falling back to heuristic linker");
    backend_fallback_evidence(plan, candidates, warnings, &warning)
}

fn codeql_flow_evidence(
    flows: Vec<super::CodeqlFlow>,
    candidates: &mut Vec<TaintIrisNextCandidate>,
    warnings: &mut Vec<String>,
) -> BackendEvidence {
    append_empty_flow_warning(
        flows.is_empty(),
        warnings,
        "codeql analyze produced no security results; reporting empty linked stories rather than synthesising heuristic ones",
    );
    let backend_path_count = flows.len();
    let mut codeql_candidates = super::codeql_flows_to_candidates(&flows);
    candidates.append(&mut codeql_candidates);
    BackendEvidence {
        linked_stories: super::codeql_flows_to_linked_stories(&flows),
        backend_path_count,
    }
}

fn joern_backend_evidence(
    plan: &TaintIrisNextPlan,
    candidates: &mut Vec<TaintIrisNextCandidate>,
    warnings: &mut Vec<String>,
) -> BackendEvidence {
    let flows = match super::run_joern_flows(plan) {
        Ok(flows) => flows,
        Err(error) => return joern_error_fallback(plan, candidates, warnings, error),
    };
    let Some(flows) = flows else {
        return backend_fallback_evidence(
            plan,
            candidates,
            warnings,
            "joern was selected but the launcher or CPG disappeared between plan and run; using heuristic linker",
        );
    };
    joern_flow_evidence(flows, candidates, warnings)
}

fn joern_error_fallback(
    plan: &TaintIrisNextPlan,
    candidates: &[TaintIrisNextCandidate],
    warnings: &mut Vec<String>,
    error: anyhow::Error,
) -> BackendEvidence {
    let warning =
        format!("joern dataflow query failed ({error}); falling back to heuristic linker");
    backend_fallback_evidence(plan, candidates, warnings, &warning)
}

fn joern_flow_evidence(
    flows: Vec<super::JoernFlow>,
    candidates: &mut Vec<TaintIrisNextCandidate>,
    warnings: &mut Vec<String>,
) -> BackendEvidence {
    append_empty_flow_warning(
        flows.is_empty(),
        warnings,
        "joern reachableByFlows found no source-to-sink paths; reporting empty linked stories rather than synthesising heuristic ones",
    );
    let backend_path_count = flows.len();
    let mut joern_candidates = super::joern_flows_to_candidates(&flows);
    candidates.append(&mut joern_candidates);
    BackendEvidence {
        linked_stories: super::joern_flows_to_linked_stories(&flows),
        backend_path_count,
    }
}

fn append_empty_flow_warning(empty: bool, warnings: &mut Vec<String>, message: &str) {
    if empty {
        warnings.push(message.to_string());
    }
}

fn backend_fallback_evidence(
    plan: &TaintIrisNextPlan,
    candidates: &[TaintIrisNextCandidate],
    warnings: &mut Vec<String>,
    warning: &str,
) -> BackendEvidence {
    warnings.push(warning.to_string());
    heuristic_backend_evidence(plan, candidates)
}

fn heuristic_backend_evidence(
    plan: &TaintIrisNextPlan,
    candidates: &[TaintIrisNextCandidate],
) -> BackendEvidence {
    BackendEvidence {
        linked_stories: build_taint_iris_next_linked_stories(candidates, &plan.cwe_focus),
        backend_path_count: 0,
    }
}

fn corroborate_with_codeql(
    plan: &TaintIrisNextPlan,
    candidates: &mut Vec<TaintIrisNextCandidate>,
    linked_stories: &mut Vec<TaintIrisNextLinkedStory>,
    backend_path_count: &mut usize,
    warnings: &mut Vec<String>,
) {
    if !should_run_codeql_corroboration(plan) {
        return;
    }
    if let Some(corroboration) = codeql_corroboration_flows(plan, warnings) {
        append_codeql_corroboration(
            candidates,
            linked_stories,
            backend_path_count,
            corroboration,
        );
    }
}

fn codeql_corroboration_flows(
    plan: &TaintIrisNextPlan,
    warnings: &mut Vec<String>,
) -> Option<Vec<super::CodeqlFlow>> {
    let flows = match super::run_codeql_flows(plan) {
        Ok(flows) => flows,
        Err(error) => {
            warnings.push(format!(
                "codeql corroboration pass failed ({error}); proceeding with rg/joern evidence only"
            ));
            return None;
        }
    };
    flows.filter(|corroboration| !corroboration.is_empty())
}

fn should_run_codeql_corroboration(plan: &TaintIrisNextPlan) -> bool {
    plan.backend.selected != "codeql" && plan.backend.corroborate_with_codeql.unwrap_or(false)
}

fn append_codeql_corroboration(
    candidates: &mut Vec<TaintIrisNextCandidate>,
    linked_stories: &mut Vec<TaintIrisNextLinkedStory>,
    backend_path_count: &mut usize,
    corroboration: Vec<super::CodeqlFlow>,
) {
    *backend_path_count += corroboration.len();
    let mut codeql_candidates = super::codeql_flows_to_candidates(&corroboration);
    candidates.append(&mut codeql_candidates);
    let mut codeql_stories = super::codeql_flows_to_linked_stories(&corroboration);
    linked_stories.append(&mut codeql_stories);
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
/// Sinks keep their marker-table intrinsic CWE (`dlopen` → CWE-94 by
/// construction). Entry points are different: a `PG_FUNCTION_INFO_V1`
/// / `@app.route` / `app.get|post` decorator is the user-controlled
/// boundary for **whatever** sink a downstream caller hits — it's a
/// CWE-78 source as much as a CWE-862 source. So when the operator
/// supplies a non-empty `cwe_focus`, project each entry point as one
/// `source` candidate per CWE in the focus set; the heuristic linker
/// can then pair across CWEs without us hardcoding per-ecosystem
/// source patterns. When `cwe_focus` is empty, fall back to the
/// marker-table CWE so an unfocused hunt still gets framework-canonical
/// CWE-862 entry points without explosion.
/// E1 bridge: walk the target's source files (same budget the
/// discovery sweep uses), run the tree-sitter identifier-injection
/// detector, and map matches into `TaintIrisNextCandidate` rows
/// honouring the operator's `cwe_focus`.
///
/// Bails to an empty Vec when:
/// - the file walker fails (target path doesn't exist, permission denied)
/// - no C/C++ files in the target
/// - `cwe_focus` is non-empty and doesn't include CWE-89
fn run_identifier_injection_detector_for_plan(
    plan: &TaintIrisNextPlan,
) -> Vec<TaintIrisNextCandidate> {
    // Match the discovery sweep's file budget so a 100k-file repo
    // doesn't double its disk-read cost just for the detector.
    let max_files = plan.caps.max_files_per_query.saturating_mul(8).max(2_000);
    let max_bytes = 256 * 1024;
    let files =
        match collect_taint_iris_next_source_files(&plan.scan_root, Some(max_files), max_bytes) {
            Ok(files) => files,
            Err(_) => return Vec::new(),
        };
    let matches = detect_identifier_injection_in_target(&plan.scan_root, &files);
    candidates_from_identifier_injection_matches(&matches, &plan.cwe_focus)
}

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
    append_discovered_sink_candidates(&mut out, signals, &allow);
    append_discovered_entry_point_candidates(&mut out, signals, cwe_focus, &allow);
    out
}

fn append_discovered_sink_candidates(
    out: &mut Vec<TaintIrisNextCandidate>,
    signals: &DiscoveredSignals,
    allow: &std::collections::BTreeSet<String>,
) {
    let mut sink_count = 0usize;
    for signal in &signals.sinks {
        if !discovered_signal_cwe_allowed(signal, allow) {
            continue;
        }
        if sink_count >= DISCOVERY_MAX_SINK_CANDIDATES {
            break;
        }
        out.push(make_discovery_candidate(
            signal,
            "sink",
            "call",
            &signal.cwe,
        ));
        sink_count += 1;
    }
}

fn append_discovered_entry_point_candidates(
    out: &mut Vec<TaintIrisNextCandidate>,
    signals: &DiscoveredSignals,
    cwe_focus: &[String],
    allow: &std::collections::BTreeSet<String>,
) {
    let entry_point_target_cwes: Vec<String> = if cwe_focus.is_empty() {
        Vec::new()
    } else {
        cwe_focus
            .iter()
            .map(|cwe| cwe.to_ascii_uppercase())
            .collect()
    };
    let per_cwe_cap = if entry_point_target_cwes.is_empty() {
        DISCOVERY_MAX_ENTRY_POINT_CANDIDATES
    } else {
        (DISCOVERY_MAX_ENTRY_POINT_CANDIDATES / entry_point_target_cwes.len()).max(1)
    };
    let mut ranked_entry_points: Vec<(&DiscoveredSignal, i32)> = signals
        .entry_points
        .iter()
        .map(|signal| (signal, entry_point_relevance_score(&signal.name)))
        .collect();
    ranked_entry_points.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.name.cmp(&b.0.name)));
    let mut entry_point_count_by_cwe: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();
    let mut total_entry_points = 0usize;
    'entry_loop: for (signal, _score) in &ranked_entry_points {
        let Some(target_cwes) = entry_point_candidate_cwes(signal, &entry_point_target_cwes, allow)
        else {
            continue;
        };
        for target_cwe in target_cwes {
            if total_entry_points >= DISCOVERY_MAX_ENTRY_POINT_CANDIDATES {
                break 'entry_loop;
            }
            let count = entry_point_count_by_cwe
                .entry(target_cwe.clone())
                .or_insert(0);
            if *count >= per_cwe_cap {
                continue;
            }
            *count += 1;
            total_entry_points += 1;
            out.push(make_discovery_candidate(
                signal,
                "source",
                "entry-point",
                &target_cwe,
            ));
        }
    }
}

fn discovered_signal_cwe_allowed(
    signal: &DiscoveredSignal,
    allow: &std::collections::BTreeSet<String>,
) -> bool {
    allow.is_empty() || allow.contains(&signal.cwe.to_ascii_uppercase())
}

fn entry_point_candidate_cwes(
    signal: &DiscoveredSignal,
    focused_cwes: &[String],
    allow: &std::collections::BTreeSet<String>,
) -> Option<Vec<String>> {
    if focused_cwes.is_empty() {
        return discovered_signal_cwe_allowed(signal, allow).then(|| vec![signal.cwe.clone()]);
    }
    Some(focused_cwes.to_vec())
}

/// Relevance score for an entry-point name when no operator-supplied
/// scoring exists. Higher = more interesting. Tokens are
/// framework-agnostic: privesc/file/process/admin verbs that appear
/// across PG (`pg_read_*`, `pg_signal_backend`), Express
/// (`/admin/exec`), Flask (`upload_file`), Java (`AdminService.exec`),
/// etc. Reading by token, not full name, lets `pg_read_binary_file`
/// score for both `read` and `file`.
fn entry_point_relevance_score(name: &str) -> i32 {
    let lower = name.to_ascii_lowercase();
    let mut score: i32 = 0;
    for token in [
        "exec",
        "system",
        "shell",
        "command",
        "run_program",
        "popen",
        "spawn",
        "load_library",
        "load_file",
        "load_external",
        "load_module",
        "dlopen",
        "dlsym",
        "import",
        "read_file",
        "read_binary",
        "read_server",
        "read_text",
        "write_file",
        "stat_file",
        "ls_dir",
        "ls_log",
        "ls_wal",
        "signal_backend",
        "signal_proc",
        "kill_backend",
        "reload_conf",
        "reload_config",
        "alter_system",
        "promote",
        "terminate",
        "cancel_backend",
        "set_user",
        "setuid",
        "admin",
        "super",
        "sudo",
        "privesc",
        "set_session",
        "switch_user",
        "become",
        "upload",
        "download",
        "evaluate",
        "eval",
        "compile",
        "parse_script",
        "lo_import",
        "lo_export",
    ] {
        if lower.contains(token) {
            score = score.saturating_add(20);
        }
    }
    // Negative bias against names that are clearly internal-only
    // (selectivity estimators, joinsel/restrictsel, _cmp, _hash) so
    // a postgres tree doesn't bury its real entry points behind
    // `_int_contained_joinsel`.
    for negative in [
        "_joinsel", "_sel", "_cmp", "_hash", "_in", "_out", "_recv", "_send", "_eq", "_lt", "_gt",
        "_le", "_ge", "_ne",
    ] {
        if lower.ends_with(negative) {
            score = score.saturating_sub(10);
        }
    }
    score
}

fn make_discovery_candidate(
    signal: &DiscoveredSignal,
    role: &'static str,
    kind: &'static str,
    target_cwe: &str,
) -> TaintIrisNextCandidate {
    TaintIrisNextCandidate {
        id: format!(
            "{}:{role}:discovered:{}:{}:{}",
            target_cwe, signal.file, signal.line, signal.name
        ),
        cwe: target_cwe.to_string(),
        taint_class: taint_class_for_discovered_cwe(target_cwe).to_string(),
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
    }
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
                signal(
                    "dlopen",
                    "CWE-94",
                    "sink",
                    "src/backend/utils/fmgr/dfmgr.c",
                    244,
                ),
                signal(
                    "system",
                    "CWE-78",
                    "sink",
                    "src/backend/access/transam/xlogarchive.c",
                    168,
                ),
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

    #[test]
    fn entry_points_project_across_cwe_focus() {
        // A discovered entry point is the user-controlled boundary —
        // for an RCE/privesc-scoped hunt it should anchor source-role
        // candidates for every focus CWE, not just the marker-table's
        // intrinsic CWE-862.
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: Vec::new(),
            sinks: Vec::new(),
            entry_points: vec![
                signal(
                    "pg_read_server_files",
                    "CWE-862",
                    "entrypoint",
                    "src/backend/utils/adt/genfile.c",
                    100,
                ),
                signal(
                    "pg_signal_backend",
                    "CWE-862",
                    "entrypoint",
                    "src/backend/utils/adt/misc.c",
                    50,
                ),
            ],
            discoverers: vec!["test".to_string()],
        };
        let cwe_focus = vec!["CWE-78".to_string(), "CWE-94".to_string()];
        let candidates = candidates_from_discovered_signals(&signals, &cwe_focus);
        // 2 entry points × 2 focus CWEs = 4 source candidates.
        assert_eq!(candidates.len(), 4);
        assert!(candidates.iter().all(|c| c.role == "source"));
        let cwes: std::collections::BTreeSet<&str> =
            candidates.iter().map(|c| c.cwe.as_str()).collect();
        assert!(cwes.contains("CWE-78"));
        assert!(cwes.contains("CWE-94"));
        // No CWE-862 anymore — the operator focused away from it.
        assert!(!cwes.contains("CWE-862"));
        // taint_class must follow the projected CWE so the linker can
        // pair source.taint_class == sink.taint_class.
        let cwe78 = candidates.iter().find(|c| c.cwe == "CWE-78").unwrap();
        assert_eq!(cwe78.taint_class, "command-injection");
        let cwe94 = candidates.iter().find(|c| c.cwe == "CWE-94").unwrap();
        assert_eq!(cwe94.taint_class, "code-injection");
    }

    #[test]
    fn entry_point_projection_partitions_cap_across_focus() {
        // 1000 entry points × 8 focus CWEs would balloon to 8000
        // candidates without the per-CWE cap. Verify the partition
        // keeps the total bounded by DISCOVERY_MAX_ENTRY_POINT_CANDIDATES.
        let mut entry_points = Vec::new();
        for line in 0..200 {
            entry_points.push(signal(
                "pg_function",
                "CWE-862",
                "entrypoint",
                "f.c",
                line as u32,
            ));
        }
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: Vec::new(),
            sinks: Vec::new(),
            entry_points,
            discoverers: vec!["test".to_string()],
        };
        let cwe_focus = vec![
            "CWE-78".to_string(),
            "CWE-94".to_string(),
            "CWE-426".to_string(),
            "CWE-269".to_string(),
        ];
        let candidates = candidates_from_discovered_signals(&signals, &cwe_focus);
        assert!(candidates.len() <= DISCOVERY_MAX_ENTRY_POINT_CANDIDATES);
        // Each focus CWE should land roughly the same share so no one
        // CWE drowns the prompt at the expense of the others.
        let per_cwe_cap = DISCOVERY_MAX_ENTRY_POINT_CANDIDATES / cwe_focus.len();
        let mut counts: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
        for c in &candidates {
            *counts.entry(c.cwe.as_str()).or_insert(0) += 1;
        }
        for (_, n) in &counts {
            assert!(*n <= per_cwe_cap);
        }
    }

    #[test]
    fn relevance_scoring_prefers_privesc_names_over_alphabetical_first() {
        // Postgres-shaped scenario: 1041 entry points where the first
        // 5 alphabetically are intarray operators (`_int_contained`)
        // and the interesting privesc primitives (`pg_read_*`,
        // `pg_signal_*`) are buried at position 600+. Without
        // relevance-aware sampling, the cap (40 / 8 focus = 5 per CWE)
        // surfaces only the irrelevant alphabetical-first entries.
        let entry_points = vec![
            signal("_int_contained", "CWE-862", "entrypoint", "f1.c", 1),
            signal("_int_contained_joinsel", "CWE-862", "entrypoint", "f1.c", 2),
            signal("_int_contains", "CWE-862", "entrypoint", "f1.c", 3),
            signal("_int_contains_joinsel", "CWE-862", "entrypoint", "f1.c", 4),
            signal("_int_eq", "CWE-862", "entrypoint", "f1.c", 5),
            signal("pg_read_server_files", "CWE-862", "entrypoint", "f2.c", 100),
            signal("pg_signal_backend", "CWE-862", "entrypoint", "f3.c", 200),
            signal("pg_reload_conf", "CWE-862", "entrypoint", "f3.c", 300),
        ];
        let signals = DiscoveredSignals {
            discovered_at_unix: 0,
            sources: Vec::new(),
            sinks: Vec::new(),
            entry_points,
            discoverers: vec!["test".to_string()],
        };
        // Single focus CWE so the cap (40) is large enough to admit
        // every entry — what we're testing is the ORDER, not the cap.
        // To force a truly tight cap, use 8 focus CWEs (5 per CWE).
        let cwe_focus = vec![
            "CWE-78".to_string(),
            "CWE-94".to_string(),
            "CWE-77".to_string(),
            "CWE-426".to_string(),
            "CWE-269".to_string(),
            "CWE-250".to_string(),
            "CWE-732".to_string(),
            "CWE-862".to_string(),
        ];
        let candidates = candidates_from_discovered_signals(&signals, &cwe_focus);
        // Group by CWE-94 only; cap is 5 per CWE.
        let cwe94_names: Vec<&str> = candidates
            .iter()
            .filter(|c| c.cwe == "CWE-94")
            .map(|c| c.pattern.as_str())
            .collect();
        assert!(
            cwe94_names.contains(&"pg_read_server_files"),
            "privesc-shaped name must beat alphabetical _int_contained when both exist; got CWE-94 candidates: {cwe94_names:?}"
        );
        assert!(
            cwe94_names.contains(&"pg_signal_backend"),
            "got CWE-94 candidates: {cwe94_names:?}"
        );
        // The intarray *_joinsel suffix is suppressed (negative bias).
        assert!(
            !cwe94_names.contains(&"_int_contained_joinsel"),
            "_joinsel suffix should be filtered out; got: {cwe94_names:?}"
        );
    }

    #[test]
    fn entry_point_relevance_score_token_coverage() {
        // Privesc / file / process tokens score positively.
        assert!(entry_point_relevance_score("pg_read_server_files") > 0);
        assert!(entry_point_relevance_score("pg_signal_backend") > 0);
        assert!(entry_point_relevance_score("load_external_function") > 0);
        assert!(entry_point_relevance_score("admin_exec") > 0);
        // Internal-only / selectivity-estimator suffixes score
        // negatively so they don't crowd out real handlers.
        assert!(entry_point_relevance_score("_int_contained_joinsel") < 0);
        assert!(entry_point_relevance_score("array_eq") < 0);
        assert!(entry_point_relevance_score("citext_cmp") < 0);
        // Neutral names score 0 — no positive or negative tokens.
        assert_eq!(entry_point_relevance_score("regular_function_name"), 0);
    }
}
