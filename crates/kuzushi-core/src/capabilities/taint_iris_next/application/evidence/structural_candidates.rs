use super::*;

pub(super) fn collect_structural_candidates(
    plan: &TaintIrisNextPlan,
) -> Result<Vec<TaintIrisNextCandidate>> {
    let files = collect_taint_iris_next_source_files(&plan.scan_root, 500, 128 * 1024)?;
    let mut state = CandidateCollectionState::default();

    for source_file in files {
        for (line_index, line) in source_file.lines.iter().enumerate() {
            state.record_line_matches(plan, &source_file, line_index, line);
        }
    }

    Ok(state.candidates)
}

const STRUCTURAL_MAX_CANDIDATES_PER_FILE_PER_CWE: usize = 6;

#[derive(Default)]
struct CandidateCollectionState {
    candidates: Vec<TaintIrisNextCandidate>,
    seen_candidate: BTreeSet<String>,
    per_query_files: BTreeMap<String, BTreeSet<String>>,
    per_cwe_candidates: BTreeMap<String, usize>,
    per_file_per_cwe_candidates: BTreeMap<(String, String), usize>,
}

impl CandidateCollectionState {
    fn record_line_matches(
        &mut self,
        plan: &TaintIrisNextPlan,
        source_file: &TaintIrisNextSourceFile,
        line_index: usize,
        line: &str,
    ) {
        let line_number = (line_index + 1) as u32;
        let lower = line.to_ascii_lowercase();
        for query in &plan.structural_queries {
            self.record_query_match(plan, source_file, line_number, line, &lower, query);
        }
    }

    fn record_query_match(
        &mut self,
        plan: &TaintIrisNextPlan,
        source_file: &TaintIrisNextSourceFile,
        line_number: u32,
        line: &str,
        lower: &str,
        query: &TaintIrisNextStructuralQuery,
    ) {
        let query_key = format!("{}:{}:{}", query.cwe, query.role, query.pattern);
        if self.query_file_cap_reached(plan, &query_key, source_file) {
            return;
        }
        if !taint_iris_next_line_matches(lower, &query.pattern) {
            return;
        }
        if self.cwe_candidate_cap_reached(plan, query) {
            return;
        }
        if self.file_cwe_candidate_cap_reached(source_file, query) {
            return;
        }

        let id = candidate_id(query, source_file, line_number);
        if !self.seen_candidate.insert(id.clone()) {
            return;
        }

        self.per_query_files
            .entry(query_key)
            .or_default()
            .insert(source_file.relative_path.clone());
        *self
            .per_cwe_candidates
            .entry(query.cwe.clone())
            .or_default() += 1;
        *self
            .per_file_per_cwe_candidates
            .entry((source_file.relative_path.clone(), query.cwe.clone()))
            .or_default() += 1;
        self.candidates
            .push(build_candidate(id, query, source_file, line_number, line));
    }

    fn query_file_cap_reached(
        &self,
        plan: &TaintIrisNextPlan,
        query_key: &str,
        source_file: &TaintIrisNextSourceFile,
    ) -> bool {
        self.per_query_files
            .get(query_key)
            .is_some_and(|files_for_query| {
                files_for_query.len() >= plan.caps.max_files_per_query
                    && !files_for_query.contains(&source_file.relative_path)
            })
    }

    fn cwe_candidate_cap_reached(
        &self,
        plan: &TaintIrisNextPlan,
        query: &TaintIrisNextStructuralQuery,
    ) -> bool {
        self.per_cwe_candidates
            .get(&query.cwe)
            .is_some_and(|count| *count >= plan.caps.max_candidates_per_cwe)
    }

    fn file_cwe_candidate_cap_reached(
        &self,
        source_file: &TaintIrisNextSourceFile,
        query: &TaintIrisNextStructuralQuery,
    ) -> bool {
        self.per_file_per_cwe_candidates
            .get(&(source_file.relative_path.clone(), query.cwe.clone()))
            .is_some_and(|count| *count >= STRUCTURAL_MAX_CANDIDATES_PER_FILE_PER_CWE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn structural_collection_caps_hot_files_per_cwe() {
        let plan = test_plan(vec![test_query("CWE-89", "sink", "query(")], 20);
        let hot_file = TaintIrisNextSourceFile {
            relative_path: "src/hot.ts".to_string(),
            language: "typescript".to_string(),
            lines: (0..20)
                .map(|line| format!("db.query(input_{line});"))
                .collect(),
        };
        let other_file = TaintIrisNextSourceFile {
            relative_path: "src/other.ts".to_string(),
            language: "typescript".to_string(),
            lines: vec!["db.query(other);".to_string()],
        };
        let mut state = CandidateCollectionState::default();

        for (line_index, line) in hot_file.lines.iter().enumerate() {
            state.record_line_matches(&plan, &hot_file, line_index, line);
        }
        state.record_line_matches(&plan, &other_file, 0, &other_file.lines[0]);

        let hot_count = state
            .candidates
            .iter()
            .filter(|candidate| candidate.file_path == "src/hot.ts")
            .count();
        assert_eq!(hot_count, STRUCTURAL_MAX_CANDIDATES_PER_FILE_PER_CWE);
        assert!(state
            .candidates
            .iter()
            .any(|candidate| candidate.file_path == "src/other.ts"));
    }

    fn test_plan(
        structural_queries: Vec<TaintIrisNextStructuralQuery>,
        max_candidates_per_cwe: usize,
    ) -> TaintIrisNextPlan {
        TaintIrisNextPlan {
            target: PathBuf::from("."),
            scan_root: PathBuf::from("."),
            repo_root: PathBuf::from("."),
            mode: TaintIrisNextMode::Hunt,
            caps: TaintIrisNextCaps {
                max_catalog_entries: 1,
                max_candidates_per_cwe,
                max_evidence_per_cwe: 10,
                max_files_per_query: 10,
                max_specs_per_cwe: 10,
                max_agent_findings: 10,
                codeql_analyze_timeout_ms: 1000,
                min_evidence_level: "candidate".to_string(),
            },
            languages: vec!["typescript".to_string()],
            context_status: TaintIrisNextArtifactStatus {
                ok: true,
                path: None,
                reason: "test".to_string(),
            },
            threat_model_status: TaintIrisNextArtifactStatus {
                ok: true,
                path: None,
                reason: "test".to_string(),
            },
            repo_context: None,
            threat_model: None,
            catalog: Vec::new(),
            structural_queries,
            prompt_catalog: String::new(),
            backend: TaintIrisNextBackendChoice {
                requested: "structural".to_string(),
                selected: "structural".to_string(),
                codeql_db_path: None,
                corroborate_with_codeql: None,
                structural_tool: "test".to_string(),
                warnings: Vec::new(),
            },
            max_budget_usd: None,
            allow_deterministic_fallback: false,
        }
    }

    fn test_query(cwe: &str, role: &str, pattern: &str) -> TaintIrisNextStructuralQuery {
        TaintIrisNextStructuralQuery {
            id: format!("{cwe}-{role}"),
            cwe: cwe.to_string(),
            taint_class: "injection".to_string(),
            role: role.to_string(),
            pattern: pattern.to_string(),
            languages: vec!["typescript".to_string()],
        }
    }
}

fn candidate_id(
    query: &TaintIrisNextStructuralQuery,
    source_file: &TaintIrisNextSourceFile,
    line_number: u32,
) -> String {
    format!(
        "{}:{}:{}:{}",
        query.cwe, query.role, source_file.relative_path, line_number
    )
}

fn build_candidate(
    id: String,
    query: &TaintIrisNextStructuralQuery,
    source_file: &TaintIrisNextSourceFile,
    line_number: u32,
    line: &str,
) -> TaintIrisNextCandidate {
    TaintIrisNextCandidate {
        id,
        cwe: query.cwe.clone(),
        taint_class: query.taint_class.clone(),
        track: candidate_track(query),
        role: query.role.clone(),
        kind: taint_iris_next_kind_for_role(&query.role).to_string(),
        pattern: query.pattern.clone(),
        file_path: source_file.relative_path.clone(),
        line: line_number,
        snippet: line.trim().to_string(),
        language: source_file.language.clone(),
        confidence: candidate_confidence(query),
        catalog_signal: format!("{}: {}", query.role, query.pattern),
        source: "structural".to_string(),
    }
}

fn candidate_track(query: &TaintIrisNextStructuralQuery) -> String {
    if query.taint_class.contains("authorization") {
        "control"
    } else {
        "taint"
    }
    .to_string()
}

fn candidate_confidence(query: &TaintIrisNextStructuralQuery) -> String {
    if matches!(query.role.as_str(), "source" | "sink") {
        "medium"
    } else {
        "low"
    }
    .to_string()
}
