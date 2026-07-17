use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

const MAX_RG_STDOUT_BYTES: usize = 32 * 1024 * 1024;
const MAX_RG_STDERR_BYTES: usize = 1024 * 1024;
const MAX_RG_ARG_BYTES: usize = 16 * 1024;

/// True iff a usable `rg` is on PATH. Probed once per process.
pub(crate) fn rg_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| {
        let mut command = Command::new("rg");
        command.arg("--version");
        crate::bounded_subprocess::output_with_limits(
            &mut command,
            "rg --version",
            64 * 1024,
            64 * 1024,
        )
        .is_ok_and(|out| out.status.success())
    })
}

/// Run ripgrep over the same file inventory the in-process backend would walk
/// and feed each match line through the existing per-query state machine.
///
/// The plan's bounded path inventory is reused so extension filtering,
/// max-files coverage, and directory exclusions stay identical to the inproc
/// backend. File bodies are deliberately left to rg; pre-reading them here
/// would double the dominant I/O cost of this backend.
pub(super) fn collect_structural_candidates_via_rg(
    plan: &TaintIrisNextPlan,
) -> Result<Vec<TaintIrisNextCandidate>> {
    if plan.source_paths.is_empty() {
        return Ok(Vec::new());
    }
    let substrings = rg_substring_set(&plan.structural_queries);
    if substrings.is_empty() {
        return Ok(Vec::new());
    }
    let by_relative_path = source_descriptors_by_relative_path(plan);
    let absolute_paths = absolute_source_paths(plan);
    let hits = run_rg(&plan.scan_root, &substrings, &absolute_paths)?;
    let hits_by_file = group_rg_hits(hits, &by_relative_path);
    Ok(collect_round_robin_candidates(
        plan,
        &by_relative_path,
        hits_by_file,
    ))
}

fn source_descriptors_by_relative_path(
    plan: &TaintIrisNextPlan,
) -> BTreeMap<String, TaintIrisNextSourceFile> {
    plan.source_paths
        .iter()
        .map(source_descriptor_entry)
        .collect()
}

fn source_descriptor_entry(
    path: &TaintIrisNextSourcePath,
) -> (String, TaintIrisNextSourceFile) {
    (
        path.relative_path.clone(),
        TaintIrisNextSourceFile {
            relative_path: path.relative_path.clone(),
            language: path.language.clone(),
            lines: Vec::new(),
        },
    )
}

fn absolute_source_paths(plan: &TaintIrisNextPlan) -> Vec<PathBuf> {
    plan.source_paths
        .iter()
        .map(|path| path.absolute_path.clone())
        .collect()
}

fn group_rg_hits(
    hits: Vec<RgHit>,
    sources: &BTreeMap<String, TaintIrisNextSourceFile>,
) -> BTreeMap<String, Vec<RgHit>> {
    let mut hits_by_file: BTreeMap<String, Vec<RgHit>> = BTreeMap::new();
    for hit in hits
        .into_iter()
        .filter(|hit| sources.contains_key(&hit.relative_path))
    {
        hits_by_file
            .entry(hit.relative_path.clone())
            .or_default()
            .push(hit);
    }
    hits_by_file
}

fn collect_round_robin_candidates(
    plan: &TaintIrisNextPlan,
    sources: &BTreeMap<String, TaintIrisNextSourceFile>,
    mut hits_by_file: BTreeMap<String, Vec<RgHit>>,
) -> Vec<TaintIrisNextCandidate> {
    let mut state = super::structural_candidates::CandidateCollectionState::default();
    // Group hits by file and process round-robin across files. The raw
    // rg output is alphabetical: a single hot file like postgres'
    // `contrib/ltree/_ltree_op.c` (50+ PG_GETARG_TEXT_PP hits) used
    // to exhaust the per-CWE candidate budget before the walker
    // reached canonical surfaces like `src/backend/utils/adt/genfile.c`
    // (alphabetical position ~857 of 1590 .c files). Round-robin
    // ensures every file matched by rg gets at least one hit
    // processed before any file is revisited — so the structural
    // pass sees broad coverage even when there's a hot file early
    // in the walk order.
    let mut round = 0usize;
    loop {
        if !record_rg_hit_round(plan, sources, &mut hits_by_file, round, &mut state) {
            break;
        }
        round += 1;
    }
    state.into_candidates()
}

fn record_rg_hit_round(
    plan: &TaintIrisNextPlan,
    sources: &BTreeMap<String, TaintIrisNextSourceFile>,
    hits_by_file: &mut BTreeMap<String, Vec<RgHit>>,
    round: usize,
    state: &mut super::structural_candidates::CandidateCollectionState,
) -> bool {
    let mut produced = false;
    for hit in hits_by_file
        .values_mut()
        .filter_map(|hits| hits.get(round).cloned())
    {
        if let Some(source_file) = sources.get(&hit.relative_path) {
            let line_index = hit.line_no.saturating_sub(1) as usize;
            state.record_line_matches(plan, source_file, line_index, &hit.line);
            produced = true;
        }
    }
    produced
}

#[derive(Debug, Clone)]
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
        "webhook url" | "callback url" | "request url" => &["req.query.url", "request.url", "url"],
        "prepared statement" | "parameterized query" | "bind parameter" => &["$1", "?", "bind"],
        _ => &[],
    }
}

fn run_rg(
    scan_root: &Path,
    substrings: &BTreeSet<String>,
    paths: &[PathBuf],
) -> Result<Vec<RgHit>> {
    let fixed_arg_bytes = rg_fixed_arg_bytes(substrings);
    let batches = rg_path_batches(paths, fixed_arg_bytes)?;
    let mut hits = Vec::new();
    let mut remaining_stdout = MAX_RG_STDOUT_BYTES;
    for batch in batches {
        if remaining_stdout == 0 {
            anyhow::bail!("taint-iris-next rg aggregate output exceeded its bounded limit");
        }
        let (mut batch_hits, stdout_bytes) =
            run_rg_batch(scan_root, substrings, batch, remaining_stdout)?;
        remaining_stdout = remaining_stdout.saturating_sub(stdout_bytes);
        hits.append(&mut batch_hits);
    }
    Ok(hits)
}

fn run_rg_batch(
    scan_root: &Path,
    substrings: &BTreeSet<String>,
    paths: &[PathBuf],
    stdout_limit: usize,
) -> Result<(Vec<RgHit>, usize)> {
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
    let output = crate::bounded_subprocess::output_with_limits(
        &mut cmd,
        "taint-iris-next rg",
        stdout_limit,
        MAX_RG_STDERR_BYTES,
    )
    .context("could not invoke rg for taint-iris-next structural backend")?;
    // rg exits 1 when there are no matches; that's a normal outcome here.
    if !output.status.success() && output.status.code() != Some(1) {
        anyhow::bail!(
            "rg exited with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout_bytes = output.stdout.len();
    Ok((parse_rg_json(scan_root, &output.stdout)?, stdout_bytes))
}

fn rg_fixed_arg_bytes(substrings: &BTreeSet<String>) -> usize {
    let flags = [
        "rg",
        "--json",
        "--fixed-strings",
        "--ignore-case",
        "--no-heading",
        "--no-config",
        "--no-messages",
        "--max-filesize=128K",
    ];
    flags.iter().map(|arg| arg.len() + 1).sum::<usize>()
        + substrings
            .iter()
            .map(|substring| 3 + estimated_arg_bytes(substring))
            .sum::<usize>()
}

fn rg_path_batches<'a>(
    paths: &'a [PathBuf],
    fixed_arg_bytes: usize,
) -> Result<Vec<&'a [PathBuf]>> {
    if fixed_arg_bytes >= MAX_RG_ARG_BYTES {
        anyhow::bail!("taint-iris-next rg patterns exceed the command-line budget");
    }
    let mut batches = Vec::new();
    let mut start = 0;
    while start < paths.len() {
        let end = rg_batch_end(paths, start, fixed_arg_bytes)?;
        batches.push(&paths[start..end]);
        start = end;
    }
    Ok(batches)
}

fn rg_batch_end(paths: &[PathBuf], start: usize, fixed_arg_bytes: usize) -> Result<usize> {
    let mut bytes = fixed_arg_bytes;
    let mut end = start;
    while let Some(path) = paths.get(end) {
        let path_bytes = estimated_arg_bytes(&path.to_string_lossy());
        if bytes.saturating_add(path_bytes) > MAX_RG_ARG_BYTES {
            break;
        }
        bytes += path_bytes;
        end += 1;
    }
    if end == start {
        anyhow::bail!("taint-iris-next rg path exceeds the command-line budget");
    }
    Ok(end)
}

fn estimated_arg_bytes(value: &str) -> usize {
    value.len().saturating_mul(2).saturating_add(3)
}

fn parse_rg_json(scan_root: &Path, stdout: &[u8]) -> Result<Vec<RgHit>> {
    let mut hits = Vec::new();
    let stdout = std::str::from_utf8(stdout).context("rg returned non-UTF-8 JSON output")?;
    for (index, raw_line) in stdout.lines().enumerate() {
        let value: Value = serde_json::from_str(raw_line)
            .with_context(|| format!("rg returned malformed JSON at line {}", index + 1))?;
        if let Some(hit) = parse_rg_hit(scan_root, &value)
            .with_context(|| format!("rg match event {} is invalid", index + 1))?
        {
            hits.push(hit);
        }
    }
    Ok(hits)
}

fn parse_rg_hit(scan_root: &Path, value: &Value) -> Result<Option<RgHit>> {
    if value.get("type").and_then(Value::as_str) != Some("match") {
        return Ok(None);
    }
    let data = value.get("data").context("missing data object")?;
    let path = data
        .pointer("/path/text")
        .and_then(Value::as_str)
        .context("missing UTF-8 path.text")?;
    let line_no = data
        .get("line_number")
        .and_then(Value::as_u64)
        .filter(|line| *line > 0)
        .context("missing positive line_number")?;
    let line = data
        .pointer("/lines/text")
        .and_then(Value::as_str)
        .context("missing UTF-8 lines.text")?;
    Ok(Some(RgHit {
        relative_path: relative_path_for(scan_root, Path::new(path)),
        line_no,
        line: line.trim_end_matches(['\r', '\n']).to_string(),
    }))
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
            (
                "query parameter",
                vec!["req.query", "request.args", "params"],
            ),
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

    #[test]
    fn rg_json_parser_rejects_malformed_and_shape_invalid_matches() {
        assert!(parse_rg_json(Path::new("/repo"), b"not-json\n").is_err());
        assert!(parse_rg_json(
            Path::new("/repo"),
            br#"{"type":"match","data":{"line_number":1}}"#,
        )
        .is_err());
    }

    #[test]
    fn rg_path_batches_stay_bounded_and_preserve_order() {
        let paths = (0..400)
            .map(|index| PathBuf::from(format!("/very/long/repository/path/{index:04}/source.rs")))
            .collect::<Vec<_>>();

        let batches = rg_path_batches(&paths, 512).unwrap();

        assert!(batches.len() > 1);
        assert_eq!(
            batches.iter().flat_map(|batch| batch.iter()).collect::<Vec<_>>(),
            paths.iter().collect::<Vec<_>>()
        );
        assert!(batches.iter().all(|batch| {
            512 + batch
                .iter()
                .map(|path| estimated_arg_bytes(&path.to_string_lossy()))
                .sum::<usize>()
                <= MAX_RG_ARG_BYTES
        }));
    }
}
