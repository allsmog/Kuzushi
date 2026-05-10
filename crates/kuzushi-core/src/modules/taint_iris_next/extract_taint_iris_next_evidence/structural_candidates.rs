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
    // No max_files cap: rg's substring search and the per-CWE candidate cap
    // already bound the work; capping the walker would silently skip files
    // alphabetically and miss whole subtrees on big repos (e.g. a 7655-file
    // postgres clone hit only 31 distinct files at the old 500-file cap,
    // missing src/backend/parser/ entirely).
    let files = collect_taint_iris_next_source_files(&plan.scan_root, None, 128 * 1024)?;
    let mut state = CandidateCollectionState::default();

    for source_file in files {
        for (line_index, line) in source_file.lines.iter().enumerate() {
            state.record_line_matches(plan, &source_file, line_index, line);
        }
    }

    Ok(state.into_candidates())
}

/// Per-file-per-CWE candidate cap. With a global per-CWE cap of e.g.
/// 80, a single hot file (postgres `contrib/ltree/_ltree_op.c` has
/// 50+ PG_GETARG_TEXT_PP hits) used to swallow the entire CWE budget
/// alphabetically before the rg walker reached canonical surfaces
/// like `src/backend/utils/adt/genfile.c`. Cap per-file so every file
/// gets a few representative candidates and the budget spreads
/// across the codebase.
const STRUCTURAL_MAX_CANDIDATES_PER_FILE_PER_CWE: usize = 6;

#[derive(Default)]
pub(super) struct CandidateCollectionState {
    candidates: Vec<TaintIrisNextCandidate>,
    seen_candidate: BTreeSet<String>,
    per_query_files: BTreeMap<String, BTreeSet<String>>,
    per_cwe_candidates: BTreeMap<String, usize>,
    per_file_per_cwe_candidates: BTreeMap<(String, String), usize>,
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
        if !query_applies_to_language(query, &source_file.language) {
            return;
        }
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

        // Diversify by file: with a global per-CWE cap of e.g. 80, a
        // single hot file (postgres `_ltree_op.c` has 50+
        // PG_GETARG_TEXT_PP hits) used to swallow the entire CWE
        // budget alphabetically before the rg walker reached
        // canonical surfaces like `genfile.c`. Cap per-file so every
        // file gets a few representative candidates.
        let per_file_key = (
            source_file.relative_path.clone(),
            query.cwe.clone(),
        );
        let per_file_count = self
            .per_file_per_cwe_candidates
            .entry(per_file_key)
            .or_default();
        if *per_file_count >= STRUCTURAL_MAX_CANDIDATES_PER_FILE_PER_CWE {
            return;
        }

        let id = candidate_id(query, source_file, line_number);
        if !self.seen_candidate.insert(id.clone()) {
            return;
        }

        files_for_query.insert(source_file.relative_path.clone());
        *cwe_count += 1;
        *per_file_count += 1;
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

/// Whether a structural query (carrying its catalog entry's `languages`) is
/// allowed to fire against a file of the given detected language.
///
/// The catalog explicitly scopes some CWEs — most notably CWE-190 (Integer
/// Overflow) restricted to `["c","cpp","go","rust"]`. Without this gate,
/// CWE-190's source signals (`length`, `size`, `count`, `offset`) and sink
/// signals (`malloc`, `resize`, `capacity`, `copy`, `slice`) match every
/// JS/TS file with `Array.length` and `.slice()` calls — which are
/// memory-safe in those languages — generating heuristic linked stories
/// that the agent then either has to reject (opus) or hallucinates findings
/// for (haiku). Same shape of false positive applies to CWE-94 patterns
/// against C/C++/Rust files, etc.
///
/// Rules:
///   - `languages == []` or contains `"any"` → unscoped, fires everywhere.
///   - `languages` lists specific languages → only fire when the file's
///     detected language is in that list.
///   - File language `"unknown"` → never fires for scoped queries (avoids
///     matching arbitrary text in non-source files like markdown).
fn query_applies_to_language(
    query: &TaintIrisNextStructuralQuery,
    file_language: &str,
) -> bool {
    if query.languages.is_empty() {
        return true;
    }
    if query.languages.iter().any(|language| language == "any") {
        return true;
    }
    query
        .languages
        .iter()
        .any(|language| language == file_language)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_with_languages(languages: &[&str]) -> TaintIrisNextStructuralQuery {
        TaintIrisNextStructuralQuery {
            id: "q".to_string(),
            cwe: "CWE-190".to_string(),
            taint_class: "integer-overflow".to_string(),
            role: "source".to_string(),
            pattern: "count".to_string(),
            languages: languages.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn cwe_190_skips_typescript_so_array_slice_is_not_a_candidate() {
        let query = query_with_languages(&["c", "cpp", "go", "rust"]);
        assert!(!query_applies_to_language(&query, "typescript"));
        assert!(!query_applies_to_language(&query, "javascript"));
        assert!(!query_applies_to_language(&query, "python"));
        assert!(query_applies_to_language(&query, "c"));
        assert!(query_applies_to_language(&query, "rust"));
    }

    #[test]
    fn any_scope_matches_every_language_including_unknown() {
        let any = query_with_languages(&["any"]);
        assert!(query_applies_to_language(&any, "typescript"));
        assert!(query_applies_to_language(&any, "unknown"));
        assert!(query_applies_to_language(&any, ""));
    }

    #[test]
    fn empty_scope_is_treated_as_any_for_legacy_catalog_entries() {
        let unscoped = query_with_languages(&[]);
        assert!(query_applies_to_language(&unscoped, "typescript"));
        assert!(query_applies_to_language(&unscoped, "rust"));
    }

    #[test]
    fn unknown_file_language_is_blocked_for_scoped_queries() {
        let scoped = query_with_languages(&["c", "rust"]);
        assert!(!query_applies_to_language(&scoped, "unknown"));
    }
}
