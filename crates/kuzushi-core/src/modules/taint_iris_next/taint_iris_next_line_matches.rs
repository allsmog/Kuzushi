use super::*;

pub(in crate::modules) fn taint_iris_next_line_matches(line_lower: &str, pattern: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    if pattern_starts_with_identifier_char(&pattern_lower) {
        if line_contains_with_identifier_word_boundary(line_lower, &pattern_lower) {
            return true;
        }
    } else if line_lower.contains(&pattern_lower) {
        return true;
    }
    taint_iris_next_alias_match(line_lower, pattern_lower.as_str())
}

/// Check whether `pattern` appears in `line` with an identifier-style
/// word boundary on the LEFT (the byte immediately before the match
/// is not an identifier char). Without this, the C catalog pattern
/// `sprintf(` matches `psprintf(` (postgres' memory-safe
/// palloc-based printf), `strcat(` matches `pg_strcat(`, etc. — and
/// floods the agent prompt with false-positive buffer-overflow
/// candidates from sites that use the safe variants.
///
/// We only enforce the LEFT boundary because most sink patterns end
/// in `(` (their own right boundary). For patterns that don't (e.g.
/// `PG_GETARG_TEXT_PP`), the next byte is always `(` in real code so
/// no right-boundary check is needed.
fn line_contains_with_identifier_word_boundary(line: &str, pattern: &str) -> bool {
    if pattern.is_empty() {
        return false;
    }
    let bytes = line.as_bytes();
    let pat_bytes = pattern.as_bytes();
    let mut idx = 0;
    while idx + pat_bytes.len() <= bytes.len() {
        if &bytes[idx..idx + pat_bytes.len()] == pat_bytes {
            // Left boundary: previous byte must not be an identifier
            // character, OR we're at the start of the line.
            let left_ok = idx == 0 || !is_identifier_byte(bytes[idx - 1]);
            if left_ok {
                return true;
            }
        }
        idx += 1;
    }
    false
}

fn is_identifier_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Most catalog sink patterns start with an identifier char
/// (`sprintf(`, `memcpy(`, `system(`, `dlopen`, `PG_GETARG_TEXT_PP`).
/// The word-boundary check only matters for those. Patterns that
/// start with a non-identifier char (e.g. `@app.route`, `req.query`,
/// `../`) fall through to the plain substring check — `@` already
/// is its own left boundary, etc.
fn pattern_starts_with_identifier_char(pattern: &str) -> bool {
    pattern
        .as_bytes()
        .first()
        .is_some_and(|b| is_identifier_byte(*b))
}

fn taint_iris_next_alias_match(line_lower: &str, pattern: &str) -> bool {
    match pattern {
        "query parameter" | "route parameter" => {
            line_lower.contains("req.query")
                || line_lower.contains("request.args")
                || line_lower.contains("params")
        }
        "request body" => line_lower.contains("req.body") || line_lower.contains("request.body"),
        "request path" => line_lower.contains("req.path") || line_lower.contains("request.path"),
        "webhook url" | "callback url" | "request url" => {
            line_lower.contains("req.query.url")
                || line_lower.contains("request.url")
                || line_lower.contains("url")
        }
        "prepared statement" | "parameterized query" | "bind parameter" => {
            line_lower.contains("$1") || line_lower.contains("?") || line_lower.contains("bind")
        }
        _ => false,
    }
}

pub(in crate::modules) fn taint_iris_next_kind_for_role(role: &str) -> &'static str {
    match role {
        "source" => "external-return-source",
        "sink" => "external-arg-sink",
        "sanitizer" => "sanitizer",
        _ => "control-context",
    }
}

pub(in crate::modules) fn build_taint_iris_next_linked_stories(
    candidates: &[TaintIrisNextCandidate],
    cwe_focus: &[String],
) -> Vec<TaintIrisNextLinkedStory> {
    let mut stories = Vec::new();
    let focus_allow: std::collections::BTreeSet<String> = cwe_focus
        .iter()
        .map(|cwe| cwe.to_ascii_uppercase())
        .collect();
    for source in candidates
        .iter()
        .filter(|candidate| candidate.role == "source")
    {
        // Drop sources that live in obviously non-production paths
        // (test harnesses, tutorials, examples, fixtures). The heuristic
        // linker has no notion of "is this code reachable from a real
        // attacker?" — a `palloc(VARSIZE_ANY_EXHDR(t))` in
        // src/tutorial/funcs.c is not exploitable because tutorial code
        // never ships in the production binary. Filtering at the source
        // side discards every linked story that would have rooted there
        // without us having to re-check inside the inner loop.
        if is_taint_iris_next_non_production_path(&source.file_path) {
            continue;
        }
        for sink in candidates.iter().filter(|candidate| candidate.role == "sink") {
            if let Some(story) =
                pair_taint_iris_next_candidates(source, sink, &focus_allow)
            {
                stories.push(story);
            }
        }
    }
    stories.sort_by(|left, right| {
        cwe_priority(&right.cwe)
            .cmp(&cwe_priority(&left.cwe))
            .then_with(|| left.file_path.cmp(&right.file_path))
            .then_with(|| left.sink_line.cmp(&right.sink_line))
    });
    stories
}

/// Decide whether a (source, sink) candidate pair forms a heuristic
/// linked story. Two pairing rules, picked by candidate provenance:
///
/// - **Discovery × Discovery (cross-file, within `cwe_focus`):** when
///   both candidates were synthesised by the framework-canonical
///   discovery sweep AND share the same `taint_class` AND both CWEs
///   are in the operator's focus set, pair them across files. This is
///   the path that surfaces e.g. a `PG_FUNCTION_INFO_V1` entry point
///   in `genfile.c` paired with `dlopen` in `dfmgr.c` for a CWE-94
///   hunt; same-file would never pair them. Discovery markers are
///   framework-canonical (PG/Flask/Express/POSIX), so the cross-file
///   rule generalises beyond postgres without us hardcoding patterns.
///
/// - **Otherwise (rg / structural / mixed):** preserve the original
///   rule — same CWE, same file, within 80 lines. rg matches on
///   substring patterns and produces noisier candidates, so the tight
///   spatial bound keeps the heuristic honest. The CWE-89 demo-repo
///   regression case is structural+structural, unaffected.
fn pair_taint_iris_next_candidates(
    source: &TaintIrisNextCandidate,
    sink: &TaintIrisNextCandidate,
    focus_allow: &std::collections::BTreeSet<String>,
) -> Option<TaintIrisNextLinkedStory> {
    let is_discovery_pair = source.source == "discovery" && sink.source == "discovery";
    let cross_file_eligible = is_discovery_pair
        && !focus_allow.is_empty()
        && focus_allow.contains(&source.cwe.to_ascii_uppercase())
        && focus_allow.contains(&sink.cwe.to_ascii_uppercase())
        && source.taint_class == sink.taint_class
        && shares_subsystem(&source.file_path, &sink.file_path);

    if !cross_file_eligible {
        if sink.cwe != source.cwe {
            return None;
        }
        if sink.file_path != source.file_path {
            return None;
        }
        if sink.line.abs_diff(source.line) > 80 {
            return None;
        }
    }

    let shared_tokens = shared_taint_iris_next_tokens(&source.snippet, &sink.snippet);
    let same_file = sink.file_path == source.file_path;
    let rationale = if cross_file_eligible && !same_file {
        format!(
            "(cross-file discovery, focus={focus}) {src_signal} source at {src_path}:{src_line} reaches {snk_signal} sink at {snk_path}:{snk_line}{tokens}",
            focus = sink.cwe,
            src_signal = source.catalog_signal,
            src_path = source.file_path,
            src_line = source.line,
            snk_signal = sink.catalog_signal,
            snk_path = sink.file_path,
            snk_line = sink.line,
            tokens = if shared_tokens.is_empty() {
                String::new()
            } else {
                format!(" with shared tokens {}", shared_tokens.join(", "))
            },
        )
    } else {
        format!(
            "{} source at line {} is near {} sink at line {}{}",
            source.catalog_signal,
            source.line,
            sink.catalog_signal,
            sink.line,
            if shared_tokens.is_empty() {
                String::new()
            } else {
                format!(" with shared tokens {}", shared_tokens.join(", "))
            }
        )
    };
    // Story CWE follows the sink because, in cross-CWE discovery
    // pairing, the sink is the load-bearing class (a `dlopen` sink is
    // CWE-94 regardless of which entry-point reached it).
    Some(TaintIrisNextLinkedStory {
        id: format!("linked-{}-{}", source.id, sink.id),
        cwe: sink.cwe.clone(),
        taint_class: sink.taint_class.clone(),
        track: source.track.clone(),
        evidence_level: "linked".to_string(),
        file_path: source.file_path.clone(),
        language: source.language.clone(),
        source_candidate_id: source.id.clone(),
        sink_candidate_id: sink.id.clone(),
        source_line: source.line,
        sink_line: sink.line,
        shared_tokens,
        rationale,
    })
}

/// Locality filter: only pair cross-file discovery candidates when
/// they share a subsystem prefix. Without this, a postgres
/// `_ltxtq_exec` (in `contrib/ltree/`) gets paired with a
/// `dlopen` (in `src/port/win32dlopen.c`) just because both are
/// discovery-tagged with the same `taint_class` — token overlap
/// across unrelated translation units that the agent rightly rejects
/// as not-a-real-flow.
///
/// The rule: pair only when source and sink either
/// (a) share the same top-level directory (`src/`, `contrib/`,
///     `lib/`, `frontend/`, `backend/`), AND
/// (b) share the same second-level directory (`contrib/ltree/`,
///     `src/backend/utils/`).
///
/// Identical-file matches always pass (the original same-file rule's
/// callers don't go through this path, but defensive). Path traversal
/// is OS-agnostic — normalise `\` → `/` first.
fn shares_subsystem(source_path: &str, sink_path: &str) -> bool {
    if source_path == sink_path {
        return true;
    }
    let source_components: Vec<&str> = source_path
        .split(|c: char| c == '/' || c == '\\')
        .filter(|s| !s.is_empty())
        .collect();
    let sink_components: Vec<&str> = sink_path
        .split(|c: char| c == '/' || c == '\\')
        .filter(|s| !s.is_empty())
        .collect();
    let depth = source_components.len().min(sink_components.len()).min(2);
    if depth < 2 {
        // Files at root (or one level deep) — accept the pair; no
        // subsystem signal to filter by.
        return true;
    }
    source_components[..depth] == sink_components[..depth]
}

/// Recognise file paths that are obviously non-production code so the
/// heuristic linker doesn't pair source/sink candidates rooted there.
/// Match is case-insensitive against any path component, so it works
/// across operating-system separators and across language conventions
/// (e.g. `src/test/`, `tests/`, `__tests__/`, `test_*.py`).
///
/// Operators who *do* want to scan non-production code (e.g. to find
/// vulns in CI fixtures shipped with a release artifact) can flip the
/// `includeNonProductionPaths` tool input — see
/// `is_non_production_paths_filter_enabled`.
pub(in crate::modules) fn is_taint_iris_next_non_production_path(file_path: &str) -> bool {
    let normalized = file_path.replace('\\', "/").to_ascii_lowercase();
    for component in normalized.split('/') {
        if matches!(
            component,
            "test"
                | "tests"
                | "__tests__"
                | "testing"
                | "tutorial"
                | "tutorials"
                | "example"
                | "examples"
                | "demo"
                | "demos"
                | "spec"
                | "specs"
                | "mock"
                | "mocks"
                | "fixture"
                | "fixtures"
                | "e2e"
                | "regress"
                | "benchmarks"
                | "bench"
                | "fuzz"
                | "fuzzing"
                | "doctest"
        ) {
            return true;
        }
    }
    // File-name level patterns: `*_test.go`, `*.test.ts`, `*.spec.js`,
    // `test_*.py`. These are language conventions for test harnesses
    // that won't ship to production.
    let last_component = normalized.rsplit('/').next().unwrap_or(&normalized);
    last_component.contains(".test.")
        || last_component.contains(".spec.")
        || last_component.starts_with("test_")
        || last_component.ends_with("_test.go")
        || last_component.ends_with("_test.py")
        || last_component.ends_with("_tests.rs")
        || last_component.ends_with("test.java")
        || last_component.ends_with("tests.java")
}

pub(in crate::modules) fn shared_taint_iris_next_tokens(left: &str, right: &str) -> Vec<String> {
    let left_tokens = identifier_tokens(left);
    let right_tokens = identifier_tokens(right);
    left_tokens
        .intersection(&right_tokens)
        .filter(|token| token.len() > 2)
        .take(8)
        .cloned()
        .collect()
}

#[cfg(test)]
mod non_production_path_tests {
    use super::*;

    #[test]
    fn drops_postgres_test_module_paths() {
        assert!(is_taint_iris_next_non_production_path(
            "src/test/modules/test_predtest/test_predtest.c"
        ));
        assert!(is_taint_iris_next_non_production_path(
            "src/test/regress/pg_regress.c"
        ));
        assert!(is_taint_iris_next_non_production_path(
            "src/tutorial/funcs.c"
        ));
        assert!(is_taint_iris_next_non_production_path(
            "src/test/modules/oauth_validator/t/oauth_server.py"
        ));
    }

    #[test]
    fn keeps_real_postgres_backend_paths() {
        assert!(!is_taint_iris_next_non_production_path(
            "src/backend/executor/nodeTidscan.c"
        ));
        assert!(!is_taint_iris_next_non_production_path(
            "src/backend/access/transam/multixact.c"
        ));
        assert!(!is_taint_iris_next_non_production_path(
            "contrib/pg_trgm/trgm_op.c"
        ));
        assert!(!is_taint_iris_next_non_production_path(
            "src/include/utils/builtins.h"
        ));
    }

    #[test]
    fn drops_javascript_test_conventions() {
        assert!(is_taint_iris_next_non_production_path(
            "frontend/tests/utils/privateApi.ts"
        ));
        assert!(is_taint_iris_next_non_production_path(
            "src/utils.test.ts"
        ));
        assert!(is_taint_iris_next_non_production_path(
            "src/utils.spec.js"
        ));
        assert!(is_taint_iris_next_non_production_path(
            "frontend/__tests__/login.tsx"
        ));
    }

    #[test]
    fn drops_python_and_go_test_filename_conventions() {
        assert!(is_taint_iris_next_non_production_path("server/test_users.py"));
        assert!(is_taint_iris_next_non_production_path(
            "internal/users_test.go"
        ));
    }

    #[test]
    fn handles_windows_separators() {
        assert!(is_taint_iris_next_non_production_path(
            "src\\test\\modules\\test_predtest\\test_predtest.c"
        ));
    }

    #[test]
    fn fixture_and_demo_dirs_are_dropped() {
        assert!(is_taint_iris_next_non_production_path(
            "evals/fixtures/demo-repo/src/routes/users.ts"
        ));
        assert!(is_taint_iris_next_non_production_path(
            "examples/sandbox-backend/server.js"
        ));
    }

    #[test]
    fn line_matches_enforces_identifier_word_boundary() {
        // `sprintf(` must match `sprintf(buf, ...)` but NOT
        // `psprintf(buf, ...)` (postgres' memory-safe palloc printf).
        // Without the word-boundary check, every postgres source file
        // using `psprintf` flooded the agent with false-positive
        // CWE-120 candidates.
        assert!(taint_iris_next_line_matches(
            "    sprintf(buf, \"hi %s\", arg);",
            "sprintf("
        ));
        assert!(!taint_iris_next_line_matches(
            "    psprintf(\"%u\", stat.blkno);",
            "sprintf("
        ));
        // Similar pairs:
        assert!(taint_iris_next_line_matches(
            "    strcpy(dest, src);",
            "strcpy("
        ));
        assert!(!taint_iris_next_line_matches(
            "    pg_strcpy(dest, src);",
            "strcpy("
        ));
        assert!(taint_iris_next_line_matches(
            "    strcat(dest, src);",
            "strcat("
        ));
        assert!(!taint_iris_next_line_matches(
            "    pg_strcat(dest, src);",
            "strcat("
        ));
        // PG_GETARG_TEXT_PP must still match (was working).
        assert!(taint_iris_next_line_matches(
            "    text *t = pg_getarg_text_pp(0);",
            "PG_GETARG_TEXT_PP"
        ));
        // Patterns that don't start with identifier chars fall through
        // to plain substring — `req.query` should match
        // `req.query.foo`.
        assert!(taint_iris_next_line_matches(
            "    const x = req.query.foo;",
            "req.query"
        ));
    }
}

#[cfg(test)]
mod linker_tests {
    use super::*;

    fn candidate(
        id: &str,
        role: &str,
        cwe: &str,
        taint_class: &str,
        file_path: &str,
        line: u32,
        source: &str,
    ) -> TaintIrisNextCandidate {
        TaintIrisNextCandidate {
            id: id.to_string(),
            cwe: cwe.to_string(),
            taint_class: taint_class.to_string(),
            track: "taint".to_string(),
            role: role.to_string(),
            kind: "test".to_string(),
            pattern: "test".to_string(),
            file_path: file_path.to_string(),
            line,
            snippet: format!("[test:{role}] dummy"),
            language: "c".to_string(),
            confidence: "medium".to_string(),
            catalog_signal: format!("{role}: dummy"),
            source: source.to_string(),
        }
    }

    #[test]
    fn pairs_discovery_source_and_sink_across_files_when_within_focus() {
        // Postgres-shaped scenario: PG_FUNCTION_INFO_V1 entry point in
        // genfile.c projected as CWE-94 source (Thread A), `dlopen` in
        // dfmgr.c as CWE-94 sink. Different files; today's same-file
        // rule would reject; the cross-file discovery rule pairs them.
        let candidates = vec![
            candidate(
                "src1",
                "source",
                "CWE-94",
                "code-injection",
                "src/backend/utils/adt/genfile.c",
                100,
                "discovery",
            ),
            candidate(
                "snk1",
                "sink",
                "CWE-94",
                "code-injection",
                "src/backend/utils/fmgr/dfmgr.c",
                244,
                "discovery",
            ),
        ];
        let cwe_focus = vec!["CWE-94".to_string()];
        let stories = build_taint_iris_next_linked_stories(&candidates, &cwe_focus);
        assert_eq!(stories.len(), 1);
        let story = &stories[0];
        assert_eq!(story.evidence_level, "linked");
        assert_eq!(story.cwe, "CWE-94");
        assert!(story.rationale.contains("cross-file discovery"));
    }

    #[test]
    fn rejects_cross_file_pair_when_focus_is_empty() {
        // Without explicit focus, the linker stays strict — the
        // cross-file discovery rule only fires when the operator opts
        // into it via cweFocus.
        let candidates = vec![
            candidate(
                "src1",
                "source",
                "CWE-94",
                "code-injection",
                "f1.c",
                10,
                "discovery",
            ),
            candidate(
                "snk1",
                "sink",
                "CWE-94",
                "code-injection",
                "f2.c",
                20,
                "discovery",
            ),
        ];
        let stories = build_taint_iris_next_linked_stories(&candidates, &[]);
        assert!(stories.is_empty());
    }

    #[test]
    fn rejects_cross_subsystem_discovery_pair() {
        // Postgres false-positive shape: an `_ltxtq_exec` source from
        // contrib/ltree paired with a `dlopen` sink in
        // src/port/win32dlopen.c. They share taint_class and CWE
        // (both CWE-94 / code-injection), but they live in
        // unrelated subsystems so a real flow between them would
        // need an unrealistic call-graph chain. The locality filter
        // suppresses this pair so the agent's prompt isn't drowned in
        // token-overlap noise.
        let candidates = vec![
            candidate(
                "src1",
                "source",
                "CWE-94",
                "code-injection",
                "contrib/ltree/_ltree_op.c",
                179,
                "discovery",
            ),
            candidate(
                "snk1",
                "sink",
                "CWE-94",
                "code-injection",
                "src/port/win32dlopen.c",
                27,
                "discovery",
            ),
        ];
        let cwe_focus = vec!["CWE-94".to_string()];
        let stories = build_taint_iris_next_linked_stories(&candidates, &cwe_focus);
        assert!(
            stories.is_empty(),
            "cross-subsystem (contrib/ltree vs src/port) pair must NOT link"
        );
    }

    #[test]
    fn rejects_cross_file_pair_when_taint_class_differs() {
        // CWE-78 (command-injection) source paired with CWE-94
        // (code-injection) sink shouldn't form a cross-file story —
        // even though both are in the focus set, the taint-class
        // mismatch indicates the source isn't the right shape for the
        // sink.
        let candidates = vec![
            candidate(
                "src1",
                "source",
                "CWE-78",
                "command-injection",
                "f1.c",
                10,
                "discovery",
            ),
            candidate(
                "snk1",
                "sink",
                "CWE-94",
                "code-injection",
                "f2.c",
                20,
                "discovery",
            ),
        ];
        let cwe_focus = vec!["CWE-78".to_string(), "CWE-94".to_string()];
        let stories = build_taint_iris_next_linked_stories(&candidates, &cwe_focus);
        assert!(stories.is_empty());
    }

    #[test]
    fn keeps_strict_rule_for_structural_candidates() {
        // The CWE-89 demo-repo regression case: rg-derived
        // structural+structural source/sink in the same file within
        // 80 lines must still pair, and a cross-file structural pair
        // (the noise we're avoiding) must NOT pair even when cwe_focus
        // would otherwise allow it.
        let same_file_candidates = vec![
            candidate(
                "src1",
                "source",
                "CWE-89",
                "sql-injection",
                "routes/users.ts",
                10,
                "structural",
            ),
            candidate(
                "snk1",
                "sink",
                "CWE-89",
                "sql-injection",
                "routes/users.ts",
                15,
                "structural",
            ),
        ];
        let stories = build_taint_iris_next_linked_stories(
            &same_file_candidates,
            &["CWE-89".to_string()],
        );
        assert_eq!(stories.len(), 1, "structural same-file pair must link");

        let cross_file_candidates = vec![
            candidate(
                "src2",
                "source",
                "CWE-89",
                "sql-injection",
                "routes/users.ts",
                10,
                "structural",
            ),
            candidate(
                "snk2",
                "sink",
                "CWE-89",
                "sql-injection",
                "routes/admin.ts",
                15,
                "structural",
            ),
        ];
        let stories = build_taint_iris_next_linked_stories(
            &cross_file_candidates,
            &["CWE-89".to_string()],
        );
        assert!(
            stories.is_empty(),
            "structural cross-file pair must NOT link even within focus"
        );
    }

    #[test]
    fn keeps_strict_rule_for_mixed_provenance() {
        // discovery source + structural sink (or vice versa) falls
        // back to the strict rule — the cross-file rule requires both
        // sides to be discovery-tagged so we trust the framework-
        // canonical marker semantics on both ends.
        let candidates = vec![
            candidate(
                "src1",
                "source",
                "CWE-94",
                "code-injection",
                "f1.c",
                10,
                "discovery",
            ),
            candidate(
                "snk1",
                "sink",
                "CWE-94",
                "code-injection",
                "f2.c",
                20,
                "structural",
            ),
        ];
        let cwe_focus = vec!["CWE-94".to_string()];
        let stories = build_taint_iris_next_linked_stories(&candidates, &cwe_focus);
        assert!(stories.is_empty());
    }
}
