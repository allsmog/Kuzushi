use super::prelude::*;
use super::*;

pub(in crate::modules) fn extract_taint_iris_next_evidence(
    plan: &TaintIrisNextPlan,
) -> Result<TaintIrisNextEvidenceResult> {
    let files = collect_taint_iris_next_source_files(&plan.scan_root, 500, 128 * 1024)?;
    let mut candidates = Vec::new();
    let mut seen_candidate = BTreeSet::new();
    let mut per_query_files: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut per_cwe_candidates: BTreeMap<String, usize> = BTreeMap::new();

    for source_file in files {
        for (line_index, line) in source_file.lines.iter().enumerate() {
            let line_number = (line_index + 1) as u32;
            let lower = line.to_ascii_lowercase();
            for query in &plan.structural_queries {
                let query_key = format!("{}:{}:{}", query.cwe, query.role, query.pattern);
                let files_for_query = per_query_files.entry(query_key).or_default();
                if files_for_query.len() >= plan.caps.max_files_per_query
                    && !files_for_query.contains(&source_file.relative_path)
                {
                    continue;
                }
                if !taint_iris_next_line_matches(&lower, &query.pattern) {
                    continue;
                }
                let cwe_count = per_cwe_candidates.entry(query.cwe.clone()).or_default();
                if *cwe_count >= plan.caps.max_candidates_per_cwe {
                    continue;
                }
                let id = format!(
                    "{}:{}:{}:{}",
                    query.cwe, query.role, source_file.relative_path, line_number
                );
                if !seen_candidate.insert(id.clone()) {
                    continue;
                }
                files_for_query.insert(source_file.relative_path.clone());
                *cwe_count += 1;
                candidates.push(TaintIrisNextCandidate {
                    id,
                    cwe: query.cwe.clone(),
                    taint_class: query.taint_class.clone(),
                    track: if query.taint_class.contains("authorization") {
                        "control".to_string()
                    } else {
                        "taint".to_string()
                    },
                    role: query.role.clone(),
                    kind: taint_iris_next_kind_for_role(&query.role).to_string(),
                    pattern: query.pattern.clone(),
                    file_path: source_file.relative_path.clone(),
                    line: line_number,
                    snippet: line.trim().to_string(),
                    language: source_file.language.clone(),
                    confidence: if matches!(query.role.as_str(), "source" | "sink") {
                        "medium".to_string()
                    } else {
                        "low".to_string()
                    },
                    catalog_signal: format!("{}: {}", query.role, query.pattern),
                    source: "structural".to_string(),
                });
            }
        }
    }

    let linked_stories = build_taint_iris_next_linked_stories(&candidates);
    let linked_by_candidate = linked_stories
        .iter()
        .flat_map(|story| {
            [
                (story.source_candidate_id.clone(), story.id.clone()),
                (story.sink_candidate_id.clone(), story.id.clone()),
            ]
        })
        .collect::<BTreeMap<_, _>>();
    let mut evidence = candidates
        .iter()
        .map(|candidate| TaintIrisNextEvidence {
            cwe: candidate.cwe.clone(),
            taint_class: candidate.taint_class.clone(),
            track: candidate.track.clone(),
            role: candidate.role.clone(),
            pattern: candidate.pattern.clone(),
            file_path: candidate.file_path.clone(),
            line: candidate.line,
            snippet: candidate.snippet.clone(),
            language: candidate.language.clone(),
            confidence: candidate.confidence.clone(),
            catalog_signal: candidate.catalog_signal.clone(),
            evidence_level: linked_by_candidate
                .get(&candidate.id)
                .map(|_| "linked")
                .unwrap_or("candidate")
                .to_string(),
            source: candidate.source.clone(),
            candidate_id: candidate.id.clone(),
            linked_story_id: linked_by_candidate.get(&candidate.id).cloned(),
        })
        .collect::<Vec<_>>();
    cap_taint_iris_next_evidence(&mut evidence, plan.caps.max_evidence_per_cwe);

    let labeled_specs = candidates
        .iter()
        .filter(|candidate| matches!(candidate.role.as_str(), "source" | "sink" | "sanitizer"))
        .take(plan.caps.max_specs_per_cwe * plan.catalog.len().max(1))
        .map(|candidate| TaintIrisNextLabeledSpec {
            id: format!("spec-{}", candidate.id),
            cwe: candidate.cwe.clone(),
            taint_class: candidate.taint_class.clone(),
            track: candidate.track.clone(),
            role: candidate.role.clone(),
            kind: candidate.kind.clone(),
            api_name: candidate.pattern.clone(),
            pattern: candidate.pattern.clone(),
            file_path: Some(candidate.file_path.clone()),
            line: Some(candidate.line),
            confidence: candidate.confidence.clone(),
            rationale: format!("Matched catalog {} signal", candidate.role),
            catalog_signal: candidate.catalog_signal.clone(),
        })
        .collect::<Vec<_>>();

    let candidate_counts = count_taint_iris_next_candidates(&candidates);
    let labeled_spec_counts = labeled_specs
        .iter()
        .fold(BTreeMap::new(), |mut counts, spec| {
            *counts.entry(spec.cwe.clone()).or_insert(0) += 1;
            counts
        });
    let linked_story_count = linked_stories.len();
    let outcome = if linked_story_count > 0 {
        "linked-evidence"
    } else if !evidence.is_empty() {
        "candidate-only"
    } else {
        "structural-only"
    };
    let finding_count = linked_story_count;
    let candidate_count = evidence.len().saturating_sub(finding_count);
    Ok(TaintIrisNextEvidenceResult {
        backend: plan.backend.selected.clone(),
        tool: if plan.backend.selected == "codeql" {
            "codeql".to_string()
        } else {
            plan.backend.structural_tool.clone()
        },
        evidence,
        candidates,
        linked_stories,
        labeled_specs,
        query_count: plan.structural_queries.len(),
        candidate_counts,
        labeled_spec_counts,
        linked_story_count,
        backend_path_count: 0,
        structural_engine: plan.backend.structural_tool.clone(),
        triage_summary: json!({
            "finding": finding_count,
            "candidate": candidate_count,
            "rejected": 0,
        }),
        outcome: outcome.to_string(),
        warnings: plan.backend.warnings.clone(),
        artifacts: json!({
            "codeqlLanguage": Value::Null,
            "codeqlQueryPath": Value::Null,
            "codeqlCompileStatus": "not-run",
        }),
    })
}
