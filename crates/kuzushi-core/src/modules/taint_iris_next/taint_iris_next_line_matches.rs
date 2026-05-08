use super::*;

pub(in crate::modules) fn taint_iris_next_line_matches(line_lower: &str, pattern: &str) -> bool {
    let pattern_lower = pattern.to_ascii_lowercase();
    if line_lower.contains(&pattern_lower) {
        return true;
    }
    taint_iris_next_alias_match(line_lower, pattern_lower.as_str())
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
) -> Vec<TaintIrisNextLinkedStory> {
    let mut stories = Vec::new();
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
        for sink in candidates
            .iter()
            .filter(|candidate| candidate.role == "sink" && candidate.cwe == source.cwe)
        {
            if sink.file_path != source.file_path {
                continue;
            }
            let distance = sink.line.abs_diff(source.line);
            if distance > 80 {
                continue;
            }
            let shared_tokens = shared_taint_iris_next_tokens(&source.snippet, &sink.snippet);
            stories.push(TaintIrisNextLinkedStory {
                id: format!("linked-{}-{}", source.id, sink.id),
                cwe: source.cwe.clone(),
                taint_class: source.taint_class.clone(),
                track: source.track.clone(),
                evidence_level: "linked".to_string(),
                file_path: source.file_path.clone(),
                language: source.language.clone(),
                source_candidate_id: source.id.clone(),
                sink_candidate_id: sink.id.clone(),
                source_line: source.line,
                sink_line: sink.line,
                shared_tokens: shared_tokens.clone(),
                rationale: format!(
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
                ),
            });
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
}
