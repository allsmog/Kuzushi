//! Inventory-derived shard candidates. Proposals are bounded and remain drafts.

use crate::modules::ToolExecutionContext;
use anyhow::{Context, Result};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Scope-size target: directories above it are split into their children.
const TARGET_SCOPE_FILES: usize = 50;
mod candidates;

const DRAFT_RELATIVE_PATH: &str = "reports/suggested-shards.toml";

/// Path segments that mark non-shipped code; such directories are skipped
/// and reported so the operator sees what was deliberately excluded.
const NON_SHIPPED_SEGMENTS: [&str; 9] = [
    "test", "tests", "spec", "specs", "fixtures", "mocks", "examples", "benches", "benchmarks",
];

pub fn execute_suggest_shards(input: &Value, ctx: &ToolExecutionContext<'_>) -> Result<Value> {
    let workspace = ctx
        .workspace
        .context("pack:suggest-shards requires an active workspace target")?;
    let root = workspace.root();
    let inventory = collect_inventory(root, ctx)?;
    let candidates::InventoryCandidates { mut candidates, excluded } =
        candidates::from_inventory(&inventory);
    rank_candidates(&mut candidates);
    let mut draft = render_draft(root, &candidates, &excluded);
    if let Some(partial) = &inventory.truncation {
        draft.push_str(&format!("\n# PARTIAL inventory: {}\n", partial.reason));
    }
    let path = write_draft(root, input, &draft)?;
    let scopes_path = emit_scopes_if_requested(root, input, &candidates, inventory.truncation.is_some())?;
    Ok(suggest_result(
        &path,
        scopes_path.as_deref(),
        &candidates,
        &excluded,
        draft,
        inventory.truncation.as_ref(),
        inventory.inspection.as_ref(),
    ))
}

fn collect_inventory(
    root: &Path,
    ctx: &ToolExecutionContext<'_>,
) -> Result<crate::workspace::RepositoryInventory> {
    let mut heartbeat = crate::progress::HeartbeatGate::new(std::time::Duration::from_secs(1));
    let mut progress = |entries| {
        if heartbeat.ready() {
            emit_inventory_progress(ctx, entries);
        }
    };
    crate::workspace::build_repository_inventory_with_observer(
        root, &mut progress, &|| ctx.is_cancelled(),
    )
}

fn emit_inventory_progress(ctx: &ToolExecutionContext<'_>, entries: usize) {
    if let Some(trace) = ctx.trace {
        let _ = trace.step("tool-progress", "pack:suggest-shards",
            format!("repository inventory · {entries} entries examined")).emit();
    }
}

/// `emitScopes=true` (the planner's DecomposeModules preset) closes the
/// decomposition loop: the same deterministic candidates become the nested
/// project-scope tree that planners and threat modeling consume. The TOML
/// draft above remains a never-auto-installed review copy.
fn emit_scopes_if_requested(
    root: &Path,
    input: &Value,
    candidates: &[ShardCandidate],
    partial: bool,
) -> Result<Option<PathBuf>> {
    let requested = input
        .get("emitScopes")
        .or_else(|| input.get("emit_scopes"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !requested {
        return Ok(None);
    }
    anyhow::ensure!(!partial, "inventory is incomplete; review the draft before accepting scan scopes");
    let tree = scope_tree_from_candidates(root, candidates);
    crate::workspace::save_nested_project_scopes(root, &tree).map(Some)
}

fn scope_tree_from_candidates(
    root: &Path,
    candidates: &[ShardCandidate],
) -> crate::workspace::NestedProjectScopeTree {
    use crate::workspace::{NestedProjectKind, NestedProjectScope};
    let mut scopes = vec![NestedProjectScope {
        id: crate::workspace::ROOT_SCOPE_ID.to_string(),
        parent: None,
        kind: NestedProjectKind::Root,
        rel_path: ".".to_string(),
        inherited_sections: Vec::new(),
    }];
    scopes.extend(candidates.iter().filter(|candidate| candidate.relative_path != ".").map(|candidate| NestedProjectScope {
        id: candidate.shard_name(),
        parent: Some(crate::workspace::ROOT_SCOPE_ID.to_string()),
        kind: NestedProjectKind::EntrypointCluster,
        rel_path: candidate.relative_path.clone(),
        inherited_sections: vec!["context-feed".into(), "threat-model".into()],
    }));
    let _ = root;
    crate::workspace::NestedProjectScopeTree {
        schema_version: 1,
        root: crate::workspace::ROOT_SCOPE_ID.to_string(),
        scopes,
    }
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
    /// Extracted entry points per inventoried file, not a confidence score.
    fn density(&self) -> f64 {
        if self.file_count == 0 {
            return 0.0;
        }
        self.signals.values().sum::<usize>() as f64 / self.file_count as f64
    }

    fn shard_name(&self) -> String {
        if self.relative_path == "." { return "repository".into(); }
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
        let digest = blake3::hash(self.relative_path.as_bytes()).to_hex();
        format!("{}-{}", slug.trim_matches('-'), &digest[..8])
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
        "# Ranked by inventoried entry points per file, then path. At most eight scopes.".to_string(),
        String::new(),
    ];
    for candidate in candidates {
        lines.push(render_candidate(candidate));
    }
    if !excluded.is_empty() {
        lines.push("# Excluded test, generated, or dependency paths:".to_string());
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
            "# WARNING: scope exceeds {TARGET_SCOPE_FILES} files; retained to preserve coverage within the proposal limits"
        ));
    }
    lines.push(format!("paths = [{}]", json!(candidate.relative_path)));
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
    let path = draft_path(root, input)?;
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("Could not create {}", parent.display()))?;
    std::fs::write(&path, draft).with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

fn draft_path(root: &Path, input: &Value) -> Result<PathBuf> {
    let requested = input
        .get("output")
        .or_else(|| input.get("out"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    crate::workspace::resolve_report_output_path(
        root,
        requested.map(Path::new),
        DRAFT_RELATIVE_PATH,
    )
    .context("pack:suggest-shards output must resolve inside the workspace root")
}

fn suggest_result(
    path: &Path,
    scopes_path: Option<&Path>,
    candidates: &[ShardCandidate],
    excluded: &[String],
    draft: String,
    partial: Option<&crate::workspace::InventoryTruncation>,
    inspection: Option<&crate::workspace::InventoryInspection>,
) -> Value {
    let oversized = candidates.iter().filter(|c| c.oversized).count();
    let scopes_line = scope_installation_note(scopes_path);
    let inventory_note = partial
        .map(|item| format!("\nPARTIAL inventory: {}", item.reason))
        .unwrap_or_default();
    let output = format!(
        "pack:suggest-shards proposed {} shard scope(s) ({} oversized, {} excluded path(s)) — draft at {}\nReview and edit the draft; it is never auto-installed.{scopes_line}{inventory_note}",
        candidates.len(),
        oversized,
        excluded.len(),
        path.display()
    );
    let data = json!({
            "inventoryComplete": partial.is_none(),
            "inventoryPartialReason": partial.map(|item| &item.reason),
            "inspection": inspection,
            "maxProposedScopes": candidates::MAX_PROPOSED_SCOPES,
            "draftPath": path.display().to_string(),
            "scopesPath": scopes_path.map(|path| path.display().to_string()),
            "shardCount": candidates.len(),
            "oversizedCount": oversized,
            "excluded": excluded,
            "draft": draft,
            "shards": candidates.iter().map(candidate_json).collect::<Vec<_>>(),
        });
    suggestion_output(output, data, partial)
}

fn suggestion_output(output: String, data: Value, partial: Option<&crate::workspace::InventoryTruncation>) -> Value {
    if let Some(partial) = partial {
        return crate::module_result::partial_output_result(
            output.clone(), output, vec![json!(partial.reason)], data,
        );
    }
    crate::module_result::completed_output_result(output.clone(), output, data)
}

fn scope_installation_note(path: Option<&Path>) -> String {
    path.map(|path| format!("\nScope tree materialized at {}.", path.display()))
        .unwrap_or_default()
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

        let mut paths: Vec<&str> = shards.iter().map(|s| s["path"].as_str().unwrap()).collect();
        paths.sort();
        assert_eq!(
            paths,
            vec!["src/api", "src/big/alpha", "src/big/beta", "src/parser", "src/quiet"],
            "{result}"
        );
        // src/big (60 files) was split into its ≤50-file children.
        assert!(shards.iter().all(|s| s["files"].as_u64().unwrap() <= 50));
        assert_eq!(result["data"]["oversizedCount"], 0);
        let excluded = result["data"]["excluded"].as_array().unwrap();
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0], "tests");
        assert!(shards.iter().all(|shard| shard["signals"]["entrypoints"].is_u64()));
        let parser = shards.iter().find(|shard| shard["path"] == "src/parser").unwrap();
        assert_eq!(parser["languages"]["c"], 3);
        assert_eq!(result["data"]["inventoryComplete"], true);
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
        // `toml` 1.x parses `Value::from_str` as a bare value expression, so a
        // whole manifest document has to go through `toml::from_str`.
        let manifest = toml::from_str::<toml::Value>(&body).unwrap();
        let shard_table = manifest.get("shards").and_then(toml::Value::as_table).unwrap();
        assert_eq!(shard_table.len(), 5);
        assert!(body.contains("# signals: entrypoints("), "{body}");
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

    #[test]
    fn partial_inventory_is_reported_and_cannot_install_scopes() {
        let temp = tempfile::tempdir().unwrap();
        write(&temp.path().join("large.rs"), &"x".repeat(256 * 1024 + 1));
        let result = run_suggest(temp.path());
        assert_eq!(result["status"], "partial");
        assert_eq!(result["data"]["inventoryComplete"], false);
        assert_eq!(result["data"]["inspection"]["truncated_files"][0], "large.rs");
        assert!(emit_scopes_if_requested(temp.path(), &json!({"emitScopes": true}), &[], true).is_err());
        assert!(crate::workspace::load_nested_project_scopes(temp.path()).unwrap().is_none());
    }

    #[test]
    fn draft_paths_are_quoted_and_scope_names_do_not_collapse() {
        let candidate = |path: &str| ShardCandidate {
            relative_path: path.into(), file_count: 1, oversized: false,
            languages: BTreeMap::new(), signals: BTreeMap::new(),
        };
        let first = candidate("src/a.b");
        let second = candidate("src/a-b");
        assert_ne!(first.shard_name(), second.shard_name());
        let quoted = candidate("src/a\"b");
        let parsed: toml::Value = toml::from_str(&render_candidate(&quoted)).unwrap();
        assert_eq!(parsed["shards"][quoted.shard_name()]["paths"][0].as_str(), Some("src/a\"b"));
        let tree = scope_tree_from_candidates(Path::new("."), &[first, second]);
        assert_eq!(tree.scopes.len(), 3);
        assert_eq!(tree.scopes[1].inherited_sections, ["context-feed", "threat-model"]);
    }

    #[test]
    fn non_source_parent_and_sibling_files_remain_covered_by_proposals() {
        for extra in ["README.md", "docs/architecture.md", "Cargo.toml"] {
            let temp = tempfile::tempdir().unwrap();
            synthetic_tree(temp.path());
            write(&temp.path().join(extra), "# repository context");
            let result = run_suggest(temp.path());
            let shards = result["data"]["shards"].as_array().unwrap();
            assert_eq!(shards.len(), 1, "{extra}: {shards:?}");
            assert_eq!(shards[0]["path"], ".", "{extra}");
            let files = result["data"]["inspection"]["files"].as_array().unwrap();
            assert!(files.iter().any(|file| file == extra));
        }
    }

    #[test]
    fn draft_path_refuses_escapes_and_defaults_under_the_state_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(tmp.path()).unwrap();

        for output in ["../escape.toml", "/tmp/shards-escape.toml"] {
            let error = draft_path(tmp.path(), &json!({ "output": output }))
                .unwrap_err()
                .to_string();
            assert!(error.contains("inside the workspace root"), "{output}: {error}");
        }

        let default = draft_path(tmp.path(), &json!({})).unwrap();
        assert_eq!(default, root.join(".kuzushi/v3/reports/suggested-shards.toml"));
    }
}
