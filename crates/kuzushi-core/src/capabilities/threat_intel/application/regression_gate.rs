use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::process::Command;

/// Outcome of running the regression gate on a single harvested entry.
///
/// The gate is a sanity check that the LLM's extracted source/sink
/// patterns actually split the world along the fix commit: the
/// pre-fix tree should still match (the bug is there), and the
/// post-fix tree should not (the bug was patched). Patterns that
/// don't split are LLM-fuzzy noise — letting them into the catalog
/// would pollute every future apply.
///
/// The gate is **structural only** — it never spins up the real hunt
/// module. That keeps each gate run cheap (no agent budget, no
/// clangd index, no LLM round-trip) and well under a second per
/// entry. Operators who want a deeper validation can re-run
/// `threat-intel:apply` with `dryRun=false` on the harvested
/// catalog; that path uses the real hunts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RegressionGateStatus {
    /// Pre-fix matched and post-fix did not. The entry is trustworthy
    /// enough to keep in the default-write set.
    Validated,
    /// We couldn't locate the fix commit in the target's git history
    /// (or the target isn't a git repo). The entry is kept as
    /// "unverified" so operators can decide whether to trust it.
    Unverified,
    /// Pre-fix and post-fix produced the same result. Either the
    /// extracted pattern is too generic (matches everything) or too
    /// specific (matches nothing). The entry is dropped from the
    /// default-write set; operators can override with
    /// `acceptRejected: true`.
    Rejected,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegressionGateOutcome {
    pub status: RegressionGateStatus,
    pub reason: String,
    #[serde(rename = "fixSha", skip_serializing_if = "Option::is_none")]
    pub fix_sha: Option<String>,
    #[serde(rename = "preFixHits", skip_serializing_if = "Option::is_none")]
    pub pre_fix_hits: Option<u32>,
    #[serde(rename = "postFixHits", skip_serializing_if = "Option::is_none")]
    pub post_fix_hits: Option<u32>,
    #[serde(rename = "filesProbed", skip_serializing_if = "Vec::is_empty", default)]
    pub files_probed: Vec<String>,
}

impl RegressionGateOutcome {
    pub fn validated(
        reason: String,
        fix_sha: String,
        pre: u32,
        post: u32,
        files: Vec<String>,
    ) -> Self {
        Self {
            status: RegressionGateStatus::Validated,
            reason,
            fix_sha: Some(fix_sha),
            pre_fix_hits: Some(pre),
            post_fix_hits: Some(post),
            files_probed: files,
        }
    }

    pub fn unverified(reason: String) -> Self {
        Self {
            status: RegressionGateStatus::Unverified,
            reason,
            fix_sha: None,
            pre_fix_hits: None,
            post_fix_hits: None,
            files_probed: Vec::new(),
        }
    }

    pub fn rejected(
        reason: String,
        fix_sha: Option<String>,
        pre: u32,
        post: u32,
        files: Vec<String>,
    ) -> Self {
        Self {
            status: RegressionGateStatus::Rejected,
            reason,
            fix_sha,
            pre_fix_hits: Some(pre),
            post_fix_hits: Some(post),
            files_probed: files,
        }
    }
}

/// Run the regression gate for one harvested entry. The function
/// returns `unverified` rather than `Err` for all "can't validate"
/// paths — git missing, fix commit not local, no affected files,
/// pattern with no structural queries — because those are normal
/// operator states, not bugs. Only IO-level errors that prevent the
/// caller from making a sensible decision propagate as `Err`.
pub fn run_regression_gate(
    target: &Path,
    cve_id: &str,
    record: &Value,
    pattern: &Value,
) -> Result<RegressionGateOutcome> {
    let queries = extract_structural_queries(pattern);
    if queries.is_empty() {
        return Ok(RegressionGateOutcome::unverified(
            "ndiff:extract-fix-pattern returned no `keywords`/`detectionQuery` to gate on — \
             accept with caution"
                .to_string(),
        ));
    }
    let fix_sha = match extract_fix_sha(record) {
        Some(sha) => sha,
        None => {
            return Ok(RegressionGateOutcome::unverified(format!(
                "no fix commit SHA discoverable from {cve_id} advisory references"
            )))
        }
    };
    let files = extract_affected_files(record, pattern);
    if files.is_empty() {
        return Ok(RegressionGateOutcome::unverified(format!(
            "no affected files declared in {cve_id} advisory; gate has nothing to read"
        )));
    }
    if !git_repo_has_commit(target, &fix_sha)? {
        return Ok(RegressionGateOutcome::unverified(format!(
            "fix commit {fix_sha} is not reachable from the target git history at {} — \
             clone with full history (`git fetch --unshallow`) to enable gating",
            target.display()
        )));
    }
    let mut pre_hits = 0u32;
    let mut post_hits = 0u32;
    let mut probed_files = Vec::with_capacity(files.len());
    for file in &files {
        let pre = git_show_file(target, &format!("{fix_sha}^"), file).ok();
        let post = git_show_file(target, &fix_sha, file).ok();
        let p_hits = pre
            .as_ref()
            .map(|text| count_query_hits(text, &queries))
            .unwrap_or(0);
        let q_hits = post
            .as_ref()
            .map(|text| count_query_hits(text, &queries))
            .unwrap_or(0);
        pre_hits = pre_hits.saturating_add(p_hits);
        post_hits = post_hits.saturating_add(q_hits);
        probed_files.push(file.clone());
    }
    classify_gate_result(fix_sha, pre_hits, post_hits, probed_files)
}

fn classify_gate_result(
    fix_sha: String,
    pre_hits: u32,
    post_hits: u32,
    files: Vec<String>,
) -> Result<RegressionGateOutcome> {
    if pre_hits == 0 && post_hits == 0 {
        return Ok(RegressionGateOutcome::rejected(
            "neither the pre-fix nor post-fix tree contains the detector's structural \
             queries; the LLM-extracted pattern is too specific (or the affected-file list \
             is wrong). Drop or re-author."
                .to_string(),
            Some(fix_sha),
            pre_hits,
            post_hits,
            files,
        ));
    }
    if pre_hits == post_hits {
        return Ok(RegressionGateOutcome::rejected(
            "pre-fix and post-fix produced the same hit count; the detector doesn't \
             distinguish the patched code. Either the pattern is too generic, or the \
             affected files weren't actually touched by this fix."
                .to_string(),
            Some(fix_sha),
            pre_hits,
            post_hits,
            files,
        ));
    }
    if pre_hits < post_hits {
        return Ok(RegressionGateOutcome::rejected(
            "post-fix has MORE detector hits than pre-fix; the polarity is inverted. \
             The pattern likely matches the new fix code rather than the old vulnerable \
             shape. Re-author."
                .to_string(),
            Some(fix_sha),
            pre_hits,
            post_hits,
            files,
        ));
    }
    Ok(RegressionGateOutcome::validated(
        format!(
            "pre-fix matched ({pre_hits} hits) and post-fix did not ({post_hits} hits); \
             the detector splits the fix commit boundary"
        ),
        fix_sha,
        pre_hits,
        post_hits,
        files,
    ))
}

fn extract_structural_queries(pattern: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(keywords) = pattern.get("keywords").and_then(Value::as_array) {
        out.extend(
            keywords
                .iter()
                .filter_map(Value::as_str)
                .filter(|s| !s.is_empty())
                .map(str::to_string),
        );
    }
    if let Some(detection) = pattern.get("detectionQuery").and_then(Value::as_str) {
        out.extend(split_pattern_phrase(detection));
    }
    if let Some(vulnerable) = pattern.get("vulnerableShape").and_then(Value::as_str) {
        out.extend(split_pattern_phrase(vulnerable));
    }
    dedup_strings(out)
}

fn split_pattern_phrase(raw: &str) -> Vec<String> {
    raw.split(|c: char| matches!(c, ',' | ';' | '\n' | '|'))
        .map(str::trim)
        .filter(|s| s.len() >= 3)
        .map(str::to_string)
        .collect()
}

fn dedup_strings(items: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

fn extract_fix_sha(record: &Value) -> Option<String> {
    let patches = record.get("patches").and_then(Value::as_array)?;
    for patch in patches {
        let url = patch.get("url").and_then(Value::as_str)?;
        if let Some(sha) = parse_commit_sha_from_url(url) {
            return Some(sha);
        }
    }
    None
}

/// Pull a commit SHA out of a GitHub commit URL or a `.patch` link.
/// Matches `.../commit/<sha>` and `.../<sha>.patch` shapes; ignores
/// pull-request URLs (those don't pin a single commit).
pub(crate) fn parse_commit_sha_from_url(url: &str) -> Option<String> {
    let needle_commit = "/commit/";
    if let Some(idx) = url.find(needle_commit) {
        let tail = &url[idx + needle_commit.len()..];
        let sha: String = tail.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        if sha.len() >= 7 {
            return Some(sha);
        }
    }
    if let Some(stripped) = url.strip_suffix(".patch") {
        let after_slash = stripped.rsplit('/').next().unwrap_or(stripped);
        let sha: String = after_slash
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if sha.len() >= 7 {
            return Some(sha);
        }
    }
    None
}

fn extract_affected_files(record: &Value, pattern: &Value) -> Vec<String> {
    let mut files = Vec::new();
    if let Some(items) = record.get("affectedFiles").and_then(Value::as_array) {
        for item in items {
            if let Some(path) = item.as_str() {
                files.push(path.to_string());
            }
        }
    }
    if let Some(items) = pattern.get("affectedFiles").and_then(Value::as_array) {
        for item in items {
            if let Some(path) = item.as_str() {
                files.push(path.to_string());
            }
        }
    }
    dedup_strings(files)
}

fn git_repo_has_commit(target: &Path, sha: &str) -> Result<bool> {
    let output = run_git(target, &["cat-file", "-e", sha])?;
    Ok(output.status.success())
}

fn git_show_file(target: &Path, rev: &str, file: &str) -> Result<String> {
    let revspec = format!("{rev}:{file}");
    let output = run_git(target, &["show", revspec.as_str()])?;
    if !output.status.success() {
        anyhow::bail!(
            "git show {revspec} in {} failed: {}",
            target.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn run_git(target: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new("git")
        .arg("-C")
        .arg(target)
        .args(args)
        .output()
        .with_context(|| {
            format!(
                "could not invoke git in {} (is git installed and is the target a repository?)",
                target.display()
            )
        })
}

fn count_query_hits(text: &str, queries: &[String]) -> u32 {
    queries
        .iter()
        .filter(|query| !query.is_empty() && text.contains(query.as_str()))
        .count() as u32
}

/// Apply the regression gate to a list of harvested entries.
/// Returns `(kept, dropped)` partitions where `kept` is the set that
/// either validated or stayed unverified, and `dropped` is the
/// rejected set (still surfaced in the operator-facing summary so
/// the failure mode is visible).
pub fn apply_regression_gate_to_entries<I>(
    target: &Path,
    accept_rejected: bool,
    entries: I,
) -> (Vec<RegressionGateOutcome>, Vec<RegressionGateOutcome>)
where
    I: IntoIterator<Item = (String, Value, Value)>, // (cve, record, pattern)
{
    let mut kept = Vec::new();
    let mut dropped = Vec::new();
    for (cve_id, record, pattern) in entries {
        let outcome = match run_regression_gate(target, &cve_id, &record, &pattern) {
            Ok(value) => value,
            Err(err) => RegressionGateOutcome::unverified(format!(
                "regression-gate error for {cve_id}: {err:#}"
            )),
        };
        match outcome.status {
            RegressionGateStatus::Rejected if !accept_rejected => dropped.push(outcome),
            _ => kept.push(outcome),
        }
    }
    (kept, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_commit_sha_from_github_commit_url() {
        let sha = parse_commit_sha_from_url(
            "https://github.com/redis/redis/commit/abcdef1234567890abcdef1234567890abcdef12",
        );
        assert_eq!(
            sha.as_deref(),
            Some("abcdef1234567890abcdef1234567890abcdef12")
        );
    }

    #[test]
    fn extracts_commit_sha_from_patch_link() {
        let sha = parse_commit_sha_from_url(
            "https://github.com/redis/redis/commit/abcdef1234567890.patch",
        );
        assert_eq!(sha.as_deref(), Some("abcdef1234567890"));
    }

    #[test]
    fn ignores_pull_request_urls() {
        // PR URLs aren't a single commit; we never gate on them.
        let sha = parse_commit_sha_from_url("https://github.com/redis/redis/pull/12345");
        assert!(sha.is_none());
    }

    #[test]
    fn unverified_when_pattern_has_no_structural_queries() {
        let outcome = run_regression_gate(
            Path::new("/nonexistent"),
            "CVE-X",
            &json!({"patches": []}),
            &json!({}),
        )
        .unwrap();
        assert_eq!(outcome.status, RegressionGateStatus::Unverified);
        assert!(
            outcome.reason.contains("structural queries")
                || outcome.reason.contains("keywords")
                || outcome.reason.contains("no `keywords`")
        );
    }

    #[test]
    fn unverified_when_fix_sha_not_in_advisory_references() {
        let outcome = run_regression_gate(
            Path::new("/nonexistent"),
            "CVE-X",
            &json!({"patches": [{"url": "https://example.com/notes"}]}),
            &json!({"keywords": ["zmalloc"]}),
        )
        .unwrap();
        assert_eq!(outcome.status, RegressionGateStatus::Unverified);
        assert!(outcome.reason.contains("fix commit"));
    }

    #[test]
    fn rejects_pattern_with_zero_hits_pre_and_post() {
        let outcome =
            classify_gate_result("abcdef".to_string(), 0, 0, vec!["src/x.c".to_string()]).unwrap();
        assert_eq!(outcome.status, RegressionGateStatus::Rejected);
        assert!(outcome.reason.contains("too specific"));
    }

    #[test]
    fn rejects_pattern_with_inverted_polarity() {
        let outcome =
            classify_gate_result("abcdef".to_string(), 1, 5, vec!["src/x.c".to_string()]).unwrap();
        assert_eq!(outcome.status, RegressionGateStatus::Rejected);
        assert!(outcome.reason.contains("polarity is inverted"));
    }

    #[test]
    fn rejects_pattern_with_equal_hits() {
        let outcome =
            classify_gate_result("abcdef".to_string(), 3, 3, vec!["src/x.c".to_string()]).unwrap();
        assert_eq!(outcome.status, RegressionGateStatus::Rejected);
        assert!(
            outcome.reason.contains("same hit count")
                || outcome.reason.contains("doesn't distinguish")
        );
    }

    #[test]
    fn validates_pattern_that_splits_pre_and_post() {
        let outcome =
            classify_gate_result("abcdef".to_string(), 5, 0, vec!["src/x.c".to_string()]).unwrap();
        assert_eq!(outcome.status, RegressionGateStatus::Validated);
        assert_eq!(outcome.pre_fix_hits, Some(5));
        assert_eq!(outcome.post_fix_hits, Some(0));
    }

    #[test]
    fn live_gate_against_real_git_repo_validates_split_pattern() {
        // Build a tiny synthetic git repo with a fix-commit boundary
        // and run the live gate against it. This exercises the real
        // `git cat-file` / `git show` paths.
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path();
        if std::process::Command::new("git")
            .arg("--version")
            .output()
            .is_err()
        {
            eprintln!("skipping live gate test: git binary not on PATH");
            return;
        }
        let run_git = |args: &[&str]| {
            std::process::Command::new("git")
                .arg("-C")
                .arg(repo)
                .args(args)
                .output()
                .expect("git invocation failed")
        };
        run_git(&["init", "-q"]);
        run_git(&["config", "user.email", "test@example.invalid"]);
        run_git(&["config", "user.name", "test"]);
        run_git(&["config", "commit.gpgsign", "false"]);
        std::fs::write(
            repo.join("vuln.c"),
            "void f() { zmalloc(count * sizeof(thing)); }\n",
        )
        .unwrap();
        run_git(&["add", "vuln.c"]);
        run_git(&["commit", "-q", "-m", "pre"]);
        std::fs::write(
            repo.join("vuln.c"),
            "void f() { if (count > LIMIT) return; zmalloc(count * sizeof(thing)); }\n",
        )
        .unwrap();
        run_git(&["add", "vuln.c"]);
        run_git(&["commit", "-q", "-m", "fix"]);
        let sha_out = run_git(&["rev-parse", "HEAD"]);
        let sha = String::from_utf8_lossy(&sha_out.stdout).trim().to_string();

        let record = json!({
            "patches": [{"url": format!("https://example.com/commit/{sha}")}],
            "affectedFiles": ["vuln.c"],
        });
        let pattern = json!({
            "keywords": ["zmalloc(count *"],
        });
        // Both pre and post contain the substring so this should reject
        // (same hit count, pattern doesn't distinguish).
        let outcome = run_regression_gate(repo, "CVE-TEST", &record, &pattern).unwrap();
        assert_eq!(outcome.status, RegressionGateStatus::Rejected);
        assert!(
            outcome.reason.contains("same hit count")
                || outcome.reason.contains("doesn't distinguish")
        );

        // A pattern that's only present pre-fix validates.
        let pattern_pre_only = json!({
            "keywords": ["void f() { zmalloc"],
        });
        let outcome = run_regression_gate(repo, "CVE-TEST", &record, &pattern_pre_only).unwrap();
        assert_eq!(outcome.status, RegressionGateStatus::Validated);
        assert!(outcome.pre_fix_hits.unwrap() > outcome.post_fix_hits.unwrap());
    }

    #[allow(dead_code)]
    fn _path_buf_marker(_p: PathBuf) {}
}
