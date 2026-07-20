//! `pack:suggest-shards` — deterministic shard-candidate proposal for a
//! fresh target (an acquisition, a new product line). NO model calls:
//! candidates come from directory file counts, language mix, entry-point
//! identifier density, and test-vs-shipped path heuristics. Emits a DRAFT
//! shards.toml under the workspace state dir, commented with the signal
//! evidence per shard, for an operator to edit — it never installs the
//! draft as `.kuzushi/shards.toml`.

use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Scope-size target: directories above it are split into their children.
const TARGET_SCOPE_FILES: usize = 50;
/// Recursion depth cap for candidate splitting.
const MAX_SPLIT_DEPTH: usize = 6;
/// Per-file content-scan byte cap; larger files count only as files.
const MAX_SCAN_BYTES: u64 = 262_144;
/// Total content-scanned file budget — keeps the walk bounded on huge trees.
const MAX_SCANNED_FILES: usize = 4000;

const DRAFT_RELATIVE_PATH: &str = "reports/suggested-shards.toml";

/// Identifier signals that mark attacker-input entry points. Substring
/// match over source text; densities feed ranking and evidence comments.
const ENTRY_SIGNALS: [&str; 10] = [
    "parse", "deserialize", "unmarshal", "decode", "recv", "listen", "accept", "handler",
    "socket", "main(",
];

const SOURCE_EXTENSIONS: [&str; 18] = [
    "c", "cc", "cpp", "cxx", "h", "hpp", "rs", "go", "py", "java", "scala", "kt", "ts", "js",
    "rb", "php", "cs", "swift",
];

/// Path segments that mark non-shipped code; such directories are skipped
/// and reported so the operator sees what was deliberately excluded.
const NON_SHIPPED_SEGMENTS: [&str; 9] = [
    "test", "tests", "spec", "specs", "fixtures", "mocks", "examples", "benches", "benchmarks",
];

/// Infrastructure directories never worth shard scopes.
const SKIPPED_DIRS: [&str; 8] = [
    "node_modules", "target", "build", "dist", "out", "vendor", ".git", "__pycache__",
];

pub fn execute_suggest_shards(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("pack:suggest-shards requires an active workspace target")?;
    let root = workspace.root();
    let mut budget = ScanBudget::default();
    let mut excluded = Vec::new();
    let mut candidates = Vec::new();
    collect_candidates(root, root, 0, &mut budget, &mut excluded, &mut candidates);
    // Non-shipped directories are recorded on every walk pass that sees them.
    excluded.sort();
    excluded.dedup();
    rank_candidates(&mut candidates);
    let draft = render_draft(root, &candidates, &excluded);
    let path = write_draft(root, input, &draft)?;
    Ok(suggest_result(&path, &candidates, &excluded, draft))
}

#[derive(Default)]
struct ScanBudget {
    scanned_files: usize,
}

#[derive(Debug)]
pub struct ShardCandidate {
    pub relative_path: String,
    pub file_count: usize,
    pub oversized: bool,
    pub languages: BTreeMap<String, usize>,
    pub signals: BTreeMap<&'static str, usize>,
}

impl ShardCandidate {
    /// Entry-signal hits per file — the ranking key. Attack-surface-dense
    /// directories (parsers, wire handlers) float to the top of the draft.
    fn density(&self) -> f64 {
        if self.file_count == 0 {
            return 0.0;
        }
        self.signals.values().sum::<usize>() as f64 / self.file_count as f64
    }

    fn shard_name(&self) -> String {
        let slug: String = self
            .relative_path
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '-'
                }
            })
            .collect();
        slug.trim_matches('-').to_string()
    }
}

/// Depth-first split: a directory whose recursive file count fits the
/// target becomes one candidate; an oversized one recurses into child
/// directories (loose files at that level are ignored — the operator sees
/// the children instead). A leaf that is still oversized is emitted with
/// an `oversized` flag rather than silently dropped.
fn collect_candidates(
    root: &Path,
    dir: &Path,
    depth: usize,
    budget: &mut ScanBudget,
    excluded: &mut Vec<String>,
    into: &mut Vec<ShardCandidate>,
) {
    let stats = directory_stats(root, dir, budget, excluded);
    if stats.file_count == 0 {
        return;
    }
    // Depth 0 always splits: the root itself is never a useful shard scope,
    // even when the whole tree fits the target size.
    if depth > 0 && (stats.file_count <= TARGET_SCOPE_FILES || depth >= MAX_SPLIT_DEPTH) {
        if let Some(candidate) = candidate_from_stats(root, dir, stats) {
            into.push(candidate);
        }
        return;
    }
    let mut children = child_directories(dir, excluded, root);
    children.sort();
    if children.is_empty() {
        if let Some(candidate) = candidate_from_stats(root, dir, stats) {
            into.push(candidate);
        }
        return;
    }
    for child in children {
        collect_candidates(root, &child, depth + 1, budget, excluded, into);
    }
}

struct DirStats {
    file_count: usize,
    languages: BTreeMap<String, usize>,
    signals: BTreeMap<&'static str, usize>,
}

fn candidate_from_stats(root: &Path, dir: &Path, stats: DirStats) -> Option<ShardCandidate> {
    let relative = dir.strip_prefix(root).ok()?;
    let relative_path = relative.to_string_lossy().replace('\\', "/");
    if relative_path.is_empty() {
        return None; // never propose the whole root as one shard
    }
    Some(ShardCandidate {
        relative_path,
        file_count: stats.file_count,
        oversized: stats.file_count > TARGET_SCOPE_FILES,
        languages: stats.languages,
        signals: stats.signals,
    })
}

fn directory_stats(
    root: &Path,
    dir: &Path,
    budget: &mut ScanBudget,
    excluded: &mut Vec<String>,
) -> DirStats {
    let mut stats = DirStats {
        file_count: 0,
        languages: BTreeMap::new(),
        signals: BTreeMap::new(),
    };
    accumulate_stats(root, dir, budget, excluded, &mut stats);
    stats
}

fn accumulate_stats(
    root: &Path,
    dir: &Path,
    budget: &mut ScanBudget,
    excluded: &mut Vec<String>,
    stats: &mut DirStats,
) {
    for entry in sorted_entries(dir) {
        if entry.is_dir() {
            if skip_directory(&entry, root, excluded) {
                continue;
            }
            accumulate_stats(root, &entry, budget, excluded, stats);
        } else if let Some(extension) = source_extension(&entry) {
            stats.file_count += 1;
            *stats.languages.entry(extension).or_insert(0) += 1;
            scan_signals(&entry, budget, &mut stats.signals);
        }
    }
}

fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|iter| iter.flatten().map(|entry| entry.path()).collect())
        .unwrap_or_default();
    entries.sort();
    entries
}

fn child_directories(dir: &Path, excluded: &mut Vec<String>, root: &Path) -> Vec<PathBuf> {
    sorted_entries(dir)
        .into_iter()
        .filter(|entry| entry.is_dir() && !skip_directory(entry, root, excluded))
        .collect()
}

fn skip_directory(dir: &Path, root: &Path, excluded: &mut Vec<String>) -> bool {
    let name = dir
        .file_name()
        .map(|name| name.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if name.starts_with('.') || SKIPPED_DIRS.contains(&name.as_str()) {
        return true;
    }
    if NON_SHIPPED_SEGMENTS.contains(&name.as_str()) {
        if let Ok(relative) = dir.strip_prefix(root) {
            excluded.push(relative.to_string_lossy().replace('\\', "/"));
        }
        return true;
    }
    false
}

fn source_extension(path: &Path) -> Option<String> {
    let extension = path.extension()?.to_string_lossy().to_lowercase();
    SOURCE_EXTENSIONS
        .contains(&extension.as_str())
        .then_some(extension)
}

fn scan_signals(path: &Path, budget: &mut ScanBudget, signals: &mut BTreeMap<&'static str, usize>) {
    if budget.scanned_files >= MAX_SCANNED_FILES {
        return;
    }
    if std::fs::metadata(path).map(|m| m.len() > MAX_SCAN_BYTES).unwrap_or(true) {
        return;
    }
    let Ok(body) = std::fs::read_to_string(path) else {
        return;
    };
    budget.scanned_files += 1;
    let lower = body.to_lowercase();
    for signal in ENTRY_SIGNALS {
        let hits = lower.matches(signal).count();
        if hits > 0 {
            *signals.entry(signal).or_insert(0) += hits;
        }
    }
}

/// Density-descending, path-ascending: attack surface first, stable output.
fn rank_candidates(candidates: &mut [ShardCandidate]) {
    candidates.sort_by(|a, b| {
        b.density()
            .partial_cmp(&a.density())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.relative_path.cmp(&b.relative_path))
    });
}

fn render_draft(root: &Path, candidates: &[ShardCandidate], excluded: &[String]) -> String {
    let mut lines = vec![
        "# DRAFT shard manifest — generated by `kuzushi run pack:suggest-shards`.".to_string(),
        format!("# Target: {}", root.display()),
        "# Review and edit before installing as <target>/.kuzushi/shards.toml:".to_string(),
        "# merge sibling scopes that share a trust boundary, rename shards after".to_string(),
        "# the boundary they cover, and delete scopes that are not attack surface.".to_string(),
        "# Ranked by entry-signal density (hits/file), then path.".to_string(),
        String::new(),
    ];
    for candidate in candidates {
        lines.push(render_candidate(candidate));
    }
    if !excluded.is_empty() {
        lines.push("# Excluded as non-shipped (tests/specs/fixtures/examples):".to_string());
        for path in excluded {
            lines.push(format!("#   {path}"));
        }
    }
    lines.join("\n")
}

fn render_candidate(candidate: &ShardCandidate) -> String {
    let mut lines = vec![format!("[shards.{}]", candidate.shard_name())];
    lines.push(format!(
        "# {} file(s) · langs: {}",
        candidate.file_count,
        join_counts(candidate.languages.iter())
    ));
    if candidate.signals.is_empty() {
        lines.push("# signals: none observed".to_string());
    } else {
        lines.push(format!(
            "# signals: {}",
            join_counts(candidate.signals.iter())
        ));
    }
    if candidate.oversized {
        lines.push(format!(
            "# WARNING: scope exceeds {TARGET_SCOPE_FILES} files with no child directories to split into — narrow by hand"
        ));
    }
    lines.push(format!("paths = [\"{}\"]", candidate.relative_path));
    lines.push(String::new());
    lines.join("\n")
}

fn join_counts<'a, K: std::fmt::Display + 'a>(
    counts: impl Iterator<Item = (K, &'a usize)>,
) -> String {
    counts
        .map(|(key, count)| format!("{key}({count})"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn write_draft(root: &Path, input: &Value, draft: &str) -> Result<PathBuf> {
    let path = draft_path(root, input);
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    std::fs::write(&path, draft).with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn draft_path(root: &Path, input: &Value) -> PathBuf {
    let requested = input
        .get("output")
        .or_else(|| input.get("out"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    match requested {
        Some(raw) if Path::new(raw).is_absolute() => PathBuf::from(raw),
        Some(raw) => root.join(raw),
        None => crate::workspace::workspace_state_dir(root).join(DRAFT_RELATIVE_PATH),
    }
}

fn suggest_result(
    path: &Path,
    candidates: &[ShardCandidate],
    excluded: &[String],
    draft: String,
) -> Value {
    let oversized = candidates.iter().filter(|c| c.oversized).count();
    let output = format!(
        "pack:suggest-shards proposed {} shard scope(s) ({} oversized, {} non-shipped dir(s) excluded) — draft at {}\nReview and edit the draft; it is never auto-installed.",
        candidates.len(),
        oversized,
        excluded.len(),
        path.display()
    );
    crate::module_result::completed_output_result(
        output.clone(),
        output,
        json!({
            "draftPath": path.display().to_string(),
            "shardCount": candidates.len(),
            "oversizedCount": oversized,
            "excluded": excluded,
            "draft": draft,
            "shards": candidates.iter().map(candidate_json).collect::<Vec<_>>(),
        }),
    )
}

fn candidate_json(candidate: &ShardCandidate) -> Value {
    json!({
        "name": candidate.shard_name(),
        "path": candidate.relative_path,
        "files": candidate.file_count,
        "oversized": candidate.oversized,
        "languages": candidate.languages,
        "signals": candidate.signals.iter().map(|(k, v)| (k.to_string(), *v)).collect::<BTreeMap<_, _>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::V2Config;
    use crate::workspace::WorkspaceTarget;

    fn write(path: &Path, body: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    /// Synthetic multi-language tree:
    /// - src/parser: 3 C files dense with parse/recv signals
    /// - src/api: 2 Go files with listen/handler signals (lower density)
    /// - src/big: 60 Python files split across two subdirectories
    /// - src/quiet: 1 signal-free Rust file
    /// - tests/: excluded as non-shipped
    fn synthetic_tree(root: &Path) {
        for index in 0..3 {
            write(
                &root.join(format!("src/parser/p{index}.c")),
                "int read_header() { parse(buf); recv(fd, buf, n, 0); parse(tail); }",
            );
        }
        for index in 0..2 {
            write(
                &root.join(format!("src/api/a{index}.go")),
                "func serve() { listen(addr); handler(w, r) }",
            );
        }
        for index in 0..30 {
            write(&root.join(format!("src/big/alpha/f{index}.py")), "x = 1\n");
            write(&root.join(format!("src/big/beta/g{index}.py")), "y = 2\n");
        }
        write(&root.join("src/quiet/lib.rs"), "pub fn add(a: u32, b: u32) -> u32 { a + b }");
        write(&root.join("tests/integration.py"), "parse('should not count')");
    }

    fn run_suggest(root: &Path) -> Value {
        let workspace = WorkspaceTarget::new(root).unwrap();
        let config = V2Config::default();
        let ctx = ToolExecutionContext {
            config: &config,
            workspace: Some(&workspace),
            findings_store: None,
            trace: None,
            cancellation: None,
            authorization: Default::default(),
        };
        execute_suggest_shards(&json!({}), &ctx).unwrap()
    }

    #[test]
    fn proposes_ranked_scoped_candidates_and_excludes_tests() {
        let tmp = tempfile::tempdir().unwrap();
        synthetic_tree(tmp.path());

        let result = run_suggest(tmp.path());
        let shards = result["data"]["shards"].as_array().unwrap();

        let paths: Vec<&str> = shards.iter().map(|s| s["path"].as_str().unwrap()).collect();
        // Density ranking: parser (8 hits / 3 files) > api (4/2) > silent dirs by path.
        assert_eq!(
            paths,
            vec!["src/parser", "src/api", "src/big/alpha", "src/big/beta", "src/quiet"],
            "{result}"
        );
        // src/big (60 files) was split into its ≤50-file children.
        assert!(shards.iter().all(|s| s["files"].as_u64().unwrap() <= 50));
        assert_eq!(result["data"]["oversizedCount"], 0);
        let excluded = result["data"]["excluded"].as_array().unwrap();
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0], "tests");
        // Signal evidence is carried per shard.
        assert_eq!(shards[0]["signals"]["parse"], 6);
        assert_eq!(shards[0]["signals"]["recv"], 3);
        assert_eq!(shards[0]["languages"]["c"], 3);
    }

    #[test]
    fn draft_is_stable_valid_toml_written_to_state_dir_not_installed() {
        let tmp = tempfile::tempdir().unwrap();
        synthetic_tree(tmp.path());

        let first = run_suggest(tmp.path());
        let second = run_suggest(tmp.path());
        assert_eq!(first["data"]["draft"], second["data"]["draft"]);

        let draft_path = PathBuf::from(first["data"]["draftPath"].as_str().unwrap());
        let body = std::fs::read_to_string(&draft_path).unwrap();
        let manifest: toml::Value = body.parse().unwrap();
        let shard_table = manifest.get("shards").and_then(toml::Value::as_table).unwrap();
        assert_eq!(shard_table.len(), 5);
        assert!(body.contains("# signals: parse(6) recv(3)"), "{body}");
        assert!(body.contains("DRAFT shard manifest"), "{body}");
        // The draft must never land at the live manifest location.
        assert!(draft_path.ends_with("reports/suggested-shards.toml"));
        assert!(!tmp.path().join(".kuzushi/shards.toml").exists());
    }

    #[test]
    fn oversized_leaf_directory_is_flagged_not_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        for index in 0..55 {
            write(&tmp.path().join(format!("flat/f{index}.c")), "int parse();");
        }

        let result = run_suggest(tmp.path());

        let shards = result["data"]["shards"].as_array().unwrap();
        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0]["path"], "flat");
        assert_eq!(shards[0]["oversized"], true);
        assert_eq!(result["data"]["oversizedCount"], 1);
        assert!(result["data"]["draft"]
            .as_str()
            .unwrap()
            .contains("WARNING: scope exceeds 50 files"));
    }
}
