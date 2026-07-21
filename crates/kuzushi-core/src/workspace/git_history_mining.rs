//! Bounded git-history vulnerability mining: grep a bounded window of the
//! target's commit history for security-fix commits so the threat-model
//! pipeline can generalize past vulns into threat classes. Every subprocess
//! is wall-clocked and output-capped; commit subjects and diffs are untrusted
//! repository data and must only reach prompts inside untrusted-source armor.

use crate::git_rev::ensure_safe_git_rev;
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct VulnCommit {
    pub sha: String,
    pub subject: String,
    pub diff_excerpt: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GitHistoryMiningConfig {
    /// Commits scanned (revision-walk window ending at HEAD). 0 disables.
    pub max_commits: usize,
    /// Matching commits kept.
    pub max_hits: usize,
    /// Matching commits that also get a diff excerpt attached.
    pub max_diff_excerpts: usize,
    /// Byte cap per diff excerpt.
    pub max_diff_bytes: usize,
    pub timeout: Duration,
}

impl Default for GitHistoryMiningConfig {
    fn default() -> Self {
        Self {
            max_commits: 300,
            max_hits: 20,
            max_diff_excerpts: 8,
            max_diff_bytes: 4096,
            timeout: Duration::from_secs(30),
        }
    }
}

/// `Ok(None)` means the target has no minable git history (not a repository,
/// no commits, or mining disabled) — never an error, because tarball-style
/// checkouts must still threat-model.
pub fn mine_vuln_history(
    target: &Path,
    keywords: &[String],
    cfg: &GitHistoryMiningConfig,
) -> Result<Option<Vec<VulnCommit>>> {
    if cfg.max_commits == 0 || keywords.is_empty() {
        return Ok(None);
    }
    let Some(window_start) = history_window_start(target, cfg) else {
        return Ok(None);
    };
    let mut commits = grep_history_window(target, keywords, cfg, window_start.as_deref())?;
    attach_diff_excerpts(target, &mut commits, cfg);
    Ok(Some(commits))
}

/// Oldest boundary of the scan window: `Some(Some(sha))` bounds the walk,
/// `Some(None)` means the whole history fits inside the window, and a `None`
/// return means the target is not a usable git repository.
fn history_window_start(target: &Path, cfg: &GitHistoryMiningConfig) -> Option<Option<String>> {
    let output = run_git(
        target,
        &[
            "rev-list",
            &format!("--max-count={}", cfg.max_commits),
            "HEAD",
        ],
        cfg.timeout,
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let shas: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    if shas.is_empty() {
        return None;
    }
    if shas.len() < cfg.max_commits {
        return Some(None);
    }
    Some(shas.last().map(|sha| sha.to_string()))
}

fn grep_history_window(
    target: &Path,
    keywords: &[String],
    cfg: &GitHistoryMiningConfig,
    window_start: Option<&str>,
) -> Result<Vec<VulnCommit>> {
    let grep = keyword_alternation(keywords);
    let max_count = format!("--max-count={}", cfg.max_hits);
    let mut args = vec![
        "log",
        "-i",
        "-E",
        "--no-merges",
        "--grep",
        &grep,
        &max_count,
        "--pretty=format:%H%x1f%s",
    ];
    let range = window_start.map(|start| format!("{start}..HEAD"));
    if let Some(range) = range.as_deref() {
        args.push(range);
    }
    let output = run_git(target, &args, cfg.timeout)?;
    if !output.status.success() {
        anyhow::bail!(
            "git history mining failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(parse_log_lines(&String::from_utf8_lossy(&output.stdout)))
}

/// Keywords are trusted curated tokens, never repo-derived; the filter keeps
/// the alternation a plain regex even if a caller slips something odd in.
fn keyword_alternation(keywords: &[String]) -> String {
    keywords
        .iter()
        .map(|keyword| {
            keyword
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '-'))
                .collect::<String>()
        })
        .filter(|keyword| !keyword.trim().is_empty())
        .collect::<Vec<_>>()
        .join("|")
}

fn parse_log_lines(stdout: &str) -> Vec<VulnCommit> {
    stdout
        .lines()
        .filter_map(|line| {
            let (sha, subject) = line.split_once('\u{1f}')?;
            Some(VulnCommit {
                sha: sha.trim().to_string(),
                subject: subject.trim().to_string(),
                diff_excerpt: None,
            })
        })
        .collect()
}

/// Best-effort enrichment: a failed `git show` leaves the excerpt `None`
/// instead of failing the mine — the commit subject is still evidence.
fn attach_diff_excerpts(target: &Path, commits: &mut [VulnCommit], cfg: &GitHistoryMiningConfig) {
    for commit in commits.iter_mut().take(cfg.max_diff_excerpts) {
        commit.diff_excerpt = diff_excerpt(target, &commit.sha, cfg);
    }
}

fn diff_excerpt(target: &Path, sha: &str, cfg: &GitHistoryMiningConfig) -> Option<String> {
    ensure_safe_git_rev(sha, "git history mining").ok()?;
    let output = run_git(
        target,
        &["show", "--no-color", "--stat", "--patch", sha],
        cfg.timeout,
    )
    .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Some(truncate_to_bytes(&text, cfg.max_diff_bytes))
}

fn truncate_to_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut cut = max_bytes;
    while cut > 0 && !text.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}\n[... diff truncated ...]", &text[..cut])
}

fn run_git(target: &Path, args: &[&str], timeout: Duration) -> Result<std::process::Output> {
    let mut command = Command::new("git");
    command.arg("-C").arg(target).args(args);
    crate::bounded_subprocess::output_with_control(
        &mut command,
        "git history mining",
        None,
        timeout,
    )
    .context("git history mining subprocess failed")
}

/// Curated commit-message keywords: a language-agnostic base plus
/// stack-specific vulnerability vocabulary. Derived from language names only —
/// never from repository content (prompt-injection boundary).
pub fn security_keywords_for_languages<'a>(
    languages: impl IntoIterator<Item = &'a str>,
) -> Vec<String> {
    let mut keywords: Vec<&str> = vec!["CVE-", "security fix", "vulnerability", "exploit"];
    let mut native = false;
    let mut web = false;
    for language in languages {
        let language = language.to_ascii_lowercase();
        native |= matches!(language.as_str(), "c" | "c++" | "cpp" | "rust" | "objective-c");
        web |= matches!(
            language.as_str(),
            "python" | "javascript" | "typescript" | "java" | "kotlin" | "go" | "scala"
                | "ruby" | "php" | "c#"
        );
    }
    if native {
        keywords.extend([
            "overflow",
            "out-of-bounds",
            "use-after-free",
            "double free",
            "integer overflow",
            "buffer",
        ]);
    }
    if web {
        keywords.extend(["injection", "SSRF", "traversal", "XSS", "CSRF", "sanitize"]);
    }
    keywords.into_iter().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@t")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@t")
            .status()
            .unwrap();
        assert!(status.success(), "git {args:?} failed");
    }

    fn fixture_repo(temp: &Path) {
        git(temp, &["init", "-q"]);
        std::fs::write(temp.join("parser.c"), "int parse() { return 0; }\n").unwrap();
        git(temp, &["add", "."]);
        git(temp, &["commit", "-q", "-m", "initial import"]);
        std::fs::write(temp.join("parser.c"), "int parse() { return 1; }\n").unwrap();
        git(temp, &["add", "."]);
        git(
            temp,
            &["commit", "-q", "-m", "fix buffer overflow in parser length check"],
        );
    }

    #[test]
    fn mines_security_fix_commits_with_diff_excerpts() {
        let temp = tempfile::tempdir().unwrap();
        fixture_repo(temp.path());
        let keywords = security_keywords_for_languages(["C"]);
        let commits = mine_vuln_history(
            temp.path(),
            &keywords,
            &GitHistoryMiningConfig::default(),
        )
        .unwrap()
        .expect("fixture repo has history");
        assert_eq!(commits.len(), 1, "only the overflow fix matches");
        assert!(commits[0].subject.contains("buffer overflow"));
        assert!(commits[0]
            .diff_excerpt
            .as_deref()
            .is_some_and(|diff| diff.contains("parser.c")));
    }

    #[test]
    fn non_git_target_yields_none_not_an_error() {
        let temp = tempfile::tempdir().unwrap();
        let keywords = security_keywords_for_languages(["C"]);
        let mined =
            mine_vuln_history(temp.path(), &keywords, &GitHistoryMiningConfig::default()).unwrap();
        assert!(mined.is_none());
    }

    #[test]
    fn zero_depth_disables_mining() {
        let temp = tempfile::tempdir().unwrap();
        fixture_repo(temp.path());
        let cfg = GitHistoryMiningConfig {
            max_commits: 0,
            ..Default::default()
        };
        let keywords = security_keywords_for_languages(["C"]);
        assert!(mine_vuln_history(temp.path(), &keywords, &cfg)
            .unwrap()
            .is_none());
    }

    #[test]
    fn diff_excerpts_are_byte_capped() {
        let temp = tempfile::tempdir().unwrap();
        fixture_repo(temp.path());
        let cfg = GitHistoryMiningConfig {
            max_diff_bytes: 32,
            ..Default::default()
        };
        let keywords = security_keywords_for_languages(["C"]);
        let commits = mine_vuln_history(temp.path(), &keywords, &cfg)
            .unwrap()
            .unwrap();
        let excerpt = commits[0].diff_excerpt.as_deref().unwrap();
        assert!(excerpt.contains("[... diff truncated ...]"));
    }

    #[test]
    fn keyword_alternation_strips_regex_metacharacters() {
        let keywords = vec!["overflow".to_string(), "a|b(".to_string()];
        assert_eq!(keyword_alternation(&keywords), "overflow|ab");
    }
}
