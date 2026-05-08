use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

/// True iff a usable `rg` is on PATH. Probed once per process.
pub(in crate::modules) fn rg_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        Command::new("rg")
            .arg("--version")
            .output()
            .is_ok_and(|out| out.status.success())
    })
}

/// Run ripgrep over the same file inventory the in-process backend would walk
/// and feed each match line through the existing per-query state machine.
///
/// The walker (`collect_taint_iris_next_source_files`) is reused so file-set
/// behavior — extension filter, null-byte gate, max-files cap, max-bytes cap,
/// `should_skip_path` exclusions — stays identical to the inproc backend.
/// Only the inner `O(files × lines × queries)` substring loop is replaced
/// with a single `rg --json --fixed-strings` invocation.
pub(super) fn collect_structural_candidates_via_rg(
    plan: &TaintIrisNextPlan,
) -> Result<Vec<TaintIrisNextCandidate>> {
    let files = collect_taint_iris_next_source_files(&plan.scan_root, 500, 128 * 1024)?;
    if files.is_empty() {
        return Ok(Vec::new());
    }
    let by_relative_path: BTreeMap<String, &TaintIrisNextSourceFile> = files
        .iter()
        .map(|file| (file.relative_path.clone(), file))
        .collect();

    let substrings = rg_substring_set(&plan.structural_queries);
    if substrings.is_empty() {
        return Ok(Vec::new());
    }

    let absolute_paths: Vec<PathBuf> = files
        .iter()
        .map(|file| plan.scan_root.join(&file.relative_path))
        .collect();

    let hits = run_rg(&plan.scan_root, &substrings, &absolute_paths)?;
    let mut state = super::structural_candidates::CandidateCollectionState::default();
    for hit in hits {
        let Some(source_file) = by_relative_path.get(&hit.relative_path).copied() else {
            continue;
        };
        let line_index = hit.line_no.saturating_sub(1) as usize;
        state.record_line_matches(plan, source_file, line_index, &hit.line);
    }
    Ok(state.into_candidates())
}

#[derive(Debug)]
struct RgHit {
    relative_path: String,
    line_no: u64,
    line: String,
}

/// Build the deduplicated substring set we hand to `rg -e`.
///
/// Catalog patterns are case-folded (we run `rg -i`) and any alias from
/// `taint_iris_next_alias_match` is added so its expansion still produces a
/// hit. Empty / multiline patterns are dropped since rg matches per-line.
fn rg_substring_set(queries: &[TaintIrisNextStructuralQuery]) -> BTreeSet<String> {
    let mut substrings = BTreeSet::new();
    for query in queries {
        let trimmed = query.pattern.trim();
        if trimmed.is_empty() || trimmed.contains('\n') {
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        for alias in alias_substrings(&lower) {
            substrings.insert((*alias).to_string());
        }
        substrings.insert(lower);
    }
    substrings
}

/// Mirror of the alias table in `taint_iris_next_line_matches.rs`.
///
/// We expand catalog patterns (e.g. "query parameter") to the concrete
/// substrings (`req.query`, `request.args`, `params`) that the in-process
/// matcher would otherwise discover via `taint_iris_next_alias_match`. The
/// catalog pattern itself is added separately by the caller, so the result
/// here is the *additional* substrings the alias table contributes.
fn alias_substrings(pattern_lower: &str) -> &'static [&'static str] {
    match pattern_lower {
        "query parameter" | "route parameter" => &["req.query", "request.args", "params"],
        "request body" => &["req.body", "request.body"],
        "request path" => &["req.path", "request.path"],
        "webhook url" | "callback url" | "request url" => {
            &["req.query.url", "request.url", "url"]
        }
        "prepared statement" | "parameterized query" | "bind parameter" => &["$1", "?", "bind"],
        _ => &[],
    }
}

fn run_rg(
    scan_root: &Path,
    substrings: &BTreeSet<String>,
    paths: &[PathBuf],
) -> Result<Vec<RgHit>> {
    let mut cmd = Command::new("rg");
    cmd.arg("--json")
        .arg("--fixed-strings")
        .arg("--ignore-case")
        .arg("--no-heading")
        .arg("--no-config")
        .arg("--no-messages")
        .arg("--max-filesize=128K");
    for substring in substrings {
        cmd.arg("-e").arg(substring);
    }
    for path in paths {
        cmd.arg(path);
    }
    let output = cmd
        .output()
        .context("could not invoke rg for taint-iris-next structural backend")?;
    // rg exits 1 when there are no matches; that's a normal outcome here.
    if !output.status.success() && output.status.code() != Some(1) {
        anyhow::bail!(
            "rg exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(parse_rg_json(scan_root, &output.stdout))
}

fn parse_rg_json(scan_root: &Path, stdout: &[u8]) -> Vec<RgHit> {
    let mut hits = Vec::new();
    let stdout = String::from_utf8_lossy(stdout);
    for raw_line in stdout.lines() {
        let value: Value = match serde_json::from_str(raw_line) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if value.get("type").and_then(Value::as_str) != Some("match") {
            continue;
        }
        let Some(data) = value.get("data") else {
            continue;
        };
        let Some(path) = data.pointer("/path/text").and_then(Value::as_str) else {
            continue;
        };
        let line_no = data.get("line_number").and_then(Value::as_u64).unwrap_or(0);
        if line_no == 0 {
            continue;
        }
        let line_text = data
            .pointer("/lines/text")
            .and_then(Value::as_str)
            .unwrap_or("");
        hits.push(RgHit {
            relative_path: relative_path_for(scan_root, Path::new(path)),
            line_no,
            line: line_text.trim_end_matches(['\r', '\n']).to_string(),
        });
    }
    hits
}

fn relative_path_for(scan_root: &Path, path: &Path) -> String {
    path.strip_prefix(scan_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alias_table_matches_in_process_matcher() {
        // Sanity: alias substrings here should round-trip through
        // `taint_iris_next_alias_match` for the same pattern. If the in-process
        // table grows a new alias, this test catches the rg side falling out
        // of sync.
        for (pattern, expansions) in [
            ("query parameter", vec!["req.query", "request.args", "params"]),
            ("request body", vec!["req.body", "request.body"]),
            ("webhook url", vec!["req.query.url", "request.url", "url"]),
        ] {
            let actual = alias_substrings(pattern);
            for expected in expansions {
                assert!(
                    actual.contains(&expected),
                    "pattern {pattern:?} should expand to {expected:?}"
                );
            }
        }
    }

    #[test]
    fn rg_substring_set_drops_empty_and_multiline_patterns() {
        let queries = vec![
            TaintIrisNextStructuralQuery {
                id: "q1".to_string(),
                cwe: "CWE-89".to_string(),
                taint_class: "injection".to_string(),
                role: "sink".to_string(),
                pattern: "query(".to_string(),
                languages: vec!["typescript".to_string()],
            },
            TaintIrisNextStructuralQuery {
                id: "q2".to_string(),
                cwe: "CWE-89".to_string(),
                taint_class: "injection".to_string(),
                role: "sink".to_string(),
                pattern: "  ".to_string(),
                languages: vec![],
            },
            TaintIrisNextStructuralQuery {
                id: "q3".to_string(),
                cwe: "CWE-89".to_string(),
                taint_class: "injection".to_string(),
                role: "source".to_string(),
                pattern: "query parameter".to_string(),
                languages: vec![],
            },
            TaintIrisNextStructuralQuery {
                id: "q4".to_string(),
                cwe: "CWE-89".to_string(),
                taint_class: "injection".to_string(),
                role: "source".to_string(),
                pattern: "with\nnewline".to_string(),
                languages: vec![],
            },
        ];
        let substrings = rg_substring_set(&queries);
        assert!(substrings.contains("query("));
        assert!(substrings.contains("query parameter"));
        assert!(substrings.contains("req.query")); // alias expansion
        assert!(substrings.contains("params")); // alias expansion
        assert!(!substrings.iter().any(|s| s.trim().is_empty()));
        assert!(!substrings.iter().any(|s| s.contains('\n')));
    }
}
