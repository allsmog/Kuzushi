use super::*;

pub(super) fn collect_structural_candidates(
    plan: &TaintIrisNextPlan,
) -> Result<Vec<TaintIrisNextCandidate>> {
    if plan.backend.structural_tool == "rg" && super::rg_available() {
        match super::rg_engine::collect_structural_candidates_via_rg(plan) {
            Ok(candidates) => return Ok(candidates),
            Err(_) => {
                // rg disappeared between detection and exec, or the JSON
                // shape drifted. Silently fall back to in-process so the
                // pipeline still produces evidence rather than blowing up
                // a long agentic run on a tooling hiccup.
            }
        }
    }
    collect_structural_candidates_inproc(plan)
}

fn collect_structural_candidates_inproc(
    plan: &TaintIrisNextPlan,
) -> Result<Vec<TaintIrisNextCandidate>> {
    let files = collect_taint_iris_next_source_files(&plan.scan_root, 500, 128 * 1024)?;
    let mut state = CandidateCollectionState::default();

    for source_file in files {
        for (line_index, line) in source_file.lines.iter().enumerate() {
            state.record_line_matches(plan, &source_file, line_index, line);
        }
    }

    Ok(state.into_candidates())
}

#[derive(Default)]
pub(super) struct CandidateCollectionState {
    candidates: Vec<TaintIrisNextCandidate>,
    seen_candidate: BTreeSet<String>,
    per_query_files: BTreeMap<String, BTreeSet<String>>,
    per_cwe_candidates: BTreeMap<String, usize>,
}

impl CandidateCollectionState {
    pub(super) fn into_candidates(self) -> Vec<TaintIrisNextCandidate> {
        self.candidates
    }

    pub(super) fn record_line_matches(
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
        let files_for_query = self.per_query_files.entry(query_key).or_default();
        if files_for_query.len() >= plan.caps.max_files_per_query
            && !files_for_query.contains(&source_file.relative_path)
        {
            return;
        }
        if !taint_iris_next_line_matches(lower, &query.pattern) {
            return;
        }

        let cwe_count = self
            .per_cwe_candidates
            .entry(query.cwe.clone())
            .or_default();
        if *cwe_count >= plan.caps.max_candidates_per_cwe {
            return;
        }

        let id = candidate_id(query, source_file, line_number);
        if !self.seen_candidate.insert(id.clone()) {
            return;
        }

        files_for_query.insert(source_file.relative_path.clone());
        *cwe_count += 1;
        self.candidates
            .push(build_candidate(id, query, source_file, line_number, line));
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
