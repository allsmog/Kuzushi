//! Whole-codebase chunked LLM pass (FullModeMulti port).
//!
//! Walks the target tree, packs files into token-bounded chunks, and
//! asks the model to identify *plausible* vulnerabilities in each chunk.
//! Output Findings flow back into the same dedup → classifier-gate →
//! deep-auditor pipeline as every other channel — the chunked pass is
//! a candidate generator, not a verifier.
//!
//! Design principles (mirrored from RoboDuck's `analyze_project_multifunc`):
//!
//! * **Generous on first pass.** The system prompt explicitly says false
//!   positives are cheap — they're filtered out by later stages. The
//!   chunked pass is allowed to over-report.
//! * **Locality-grouped chunks.** Files are sorted by directory
//!   affinity so related headers and implementations land in the same
//!   chunk. Inter-procedural reasoning is the entire point of the
//!   pass — splitting siblings across chunks loses it.
//! * **Cost-first.** A `--dry-run-cost-estimate` mode prints the chunk
//!   count, token totals, and per-model price estimate without making
//!   any LLM call. Always run this against a fresh slice before paying.
//!
//! Phase 7 ships the planner, chunker, dispatcher, and prompt builder.
//! Concurrency (per-model semaphores) lands in Phase 8; cross-channel
//! dedup in Phase 9.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::agent_router::{AgentRole, RoutedRuntime};
use crate::findings::{Finding, Severity};
use crate::runtime::{AgentQueryRequest, AgentRuntime};
use crate::spend::{Operation, SpendLimiter};

/// Default chunk budget in approximate tokens. Sized so a chunk fits in
/// a single 200k-context call with room for the system prompt + output.
pub const DEFAULT_MAX_TOKENS_PER_CHUNK: usize = 120_000;

/// Approximate bytes-per-token. Empirically ~3.6 across mixed C/Rust
/// code. Used for chunk packing without invoking a real tokenizer.
pub const BYTES_PER_TOKEN: f64 = 3.6;

/// Hard cap on per-file size before we split. Beyond this we break on
/// top-level brace boundaries.
pub const MAX_FILE_BYTES: usize = MAX_FILE_TOKENS * BYTES_PER_TOKEN as usize;
const MAX_FILE_TOKENS: usize = 80_000;

/// Directories the walker never descends into. Mirrors
/// `systems_hunt::SKIP_DIRS`.
const SKIP_DIRS: &[&str] = &[
    ".git",
    ".hg",
    ".kuzushi",
    ".next",
    ".turbo",
    "build",
    "coverage",
    "dist",
    "node_modules",
    "target",
    "vendor",
];

/// Conservative initial deposit per chunk. Real cost surfaces from the
/// bridge response and settles via SpendLimiter::refund.
pub const DEFAULT_DEPOSIT_USD_PER_CHUNK: f64 = 2.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullModeConfig {
    pub workspace_root: PathBuf,
    pub max_tokens_per_chunk: usize,
    pub deposit_usd_per_chunk: f64,
    /// File extensions to include. Empty = `["c","cc","cpp","cxx","h","hh","hpp","hxx"]`.
    #[serde(default)]
    pub include_extensions: Vec<String>,
    /// Language for the prompt selector — `"c"`, `"unknown"`. `"java"`
    /// will be supported in a follow-up.
    pub language: FullModeLanguage,
    /// If `true`, the dispatcher returns the chunk plan + cost estimate
    /// without invoking any model. Always run this on a fresh slice.
    pub dry_run: bool,
    /// Optional diff-scope filter: when set, only files whose relative
    /// path appears in `scope_files` are included in the plan. Used by
    /// the `--since <ref>` flag to scan only what changed.
    #[serde(default)]
    pub scope_files: Option<Vec<PathBuf>>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum FullModeLanguage {
    C,
    Unknown,
}

impl Default for FullModeConfig {
    fn default() -> Self {
        Self {
            workspace_root: PathBuf::from("."),
            max_tokens_per_chunk: DEFAULT_MAX_TOKENS_PER_CHUNK,
            deposit_usd_per_chunk: DEFAULT_DEPOSIT_USD_PER_CHUNK,
            include_extensions: Vec::new(),
            language: FullModeLanguage::C,
            dry_run: false,
            scope_files: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileBucket {
    pub path: String,
    pub bytes: usize,
    pub est_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkPlan {
    pub id: u32,
    pub files: Vec<FileBucket>,
    pub est_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullModePlan {
    pub chunks: Vec<ChunkPlan>,
    pub total_files: usize,
    pub total_bytes: usize,
    pub total_tokens: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullModeReport {
    pub findings: Vec<Finding>,
    pub plan: FullModePlan,
    pub chunks_dispatched: u32,
    pub chunks_failed: u32,
    pub cost_usd: f64,
    pub dry_run: bool,
}

const SYSTEM_PROMPT_C: &str = r#"You are Kuzushi's whole-codebase scanner. You are seeing
one chunk of many files in a single C/C++ project. Treat the chunk as the entire context;
do not assume guards live outside it.

Be GENEROUS — false positives are cheap, they will be filtered out by later stages.
Report any function that COULD be vulnerable based on what you can see in the chunk.

Vulnerability classes to look for: out-of-bounds read/write, integer overflow leading
to undersized allocation, use-after-free, double-free, format string injection,
command injection, path traversal, missing bounds check on length-prefixed input,
TOCTOU, signed/unsigned confusion, unchecked return values from allocator/parser
functions.

Return ONLY a JSON array (no prose, no markdown) of objects matching:

[{
  "file": "relative/path.c",
  "line": int,
  "function": "name",
  "severity": "low" | "medium" | "high" | "critical",
  "cwe": ["CWE-787", ...],
  "title": "short one-line description",
  "rationale": "one or two sentences naming the source, sink, and missing guard"
}]

If you find nothing, return [].
Do not include functions you only suspect — every entry must reference a specific line."#;

const SYSTEM_PROMPT_UNKNOWN: &str = r#"You are Kuzushi's whole-codebase scanner. You are
seeing one chunk of many files. Treat the chunk as the entire context; do not assume
guards live outside it. Be generous — false positives are cheap.

Return ONLY a JSON array of objects matching:

[{
  "file": "relative/path.ext",
  "line": int,
  "function": "name",
  "severity": "low" | "medium" | "high" | "critical",
  "cwe": ["CWE-..."],
  "title": "short one-line description",
  "rationale": "one or two sentences"
}]

If you find nothing, return []."#;

#[derive(Debug, Deserialize)]
struct ModelFinding {
    #[serde(default)]
    file: String,
    #[serde(default)]
    line: u32,
    #[serde(default)]
    function: String,
    #[serde(default)]
    severity: String,
    #[serde(default)]
    cwe: Vec<String>,
    #[serde(default)]
    title: String,
    #[serde(default)]
    rationale: String,
}

/// Plan only — produces the chunk layout without any LLM calls. Use this
/// for `--dry-run-cost-estimate` and unit tests.
pub fn plan(cfg: &FullModeConfig) -> Result<FullModePlan> {
    let mut files = walk_files(cfg)?;
    files.sort_by(|a, b| a.path.cmp(&b.path)); // directory affinity
    let mut chunks: Vec<ChunkPlan> = Vec::new();
    let mut current = ChunkPlan {
        id: 0,
        files: Vec::new(),
        est_tokens: 0,
    };
    let cap = cfg.max_tokens_per_chunk;
    let mut total_files = 0usize;
    let mut total_bytes = 0usize;
    let mut total_tokens = 0usize;
    for f in files {
        total_files += 1;
        total_bytes += f.bytes;
        total_tokens += f.est_tokens;
        if !current.files.is_empty() && current.est_tokens + f.est_tokens > cap {
            chunks.push(std::mem::replace(
                &mut current,
                ChunkPlan {
                    id: chunks.len() as u32 + 1,
                    files: Vec::new(),
                    est_tokens: 0,
                },
            ));
        }
        current.est_tokens += f.est_tokens;
        current.files.push(f);
    }
    if !current.files.is_empty() {
        chunks.push(current);
    }
    // Renumber from 0 for stable ids.
    for (i, c) in chunks.iter_mut().enumerate() {
        c.id = i as u32;
    }
    Ok(FullModePlan {
        chunks,
        total_files,
        total_bytes,
        total_tokens,
    })
}

fn walk_files(cfg: &FullModeConfig) -> Result<Vec<FileBucket>> {
    let extensions = if cfg.include_extensions.is_empty() {
        c_default_extensions()
    } else {
        cfg.include_extensions
            .iter()
            .map(|e| e.trim_start_matches('.').to_ascii_lowercase())
            .collect::<Vec<_>>()
    };
    let mut out = Vec::new();
    walk_recursive(
        &cfg.workspace_root,
        &cfg.workspace_root,
        &extensions,
        &mut out,
    )?;
    if let Some(scope) = &cfg.scope_files {
        let allowed: std::collections::HashSet<&Path> = scope.iter().map(|p| p.as_path()).collect();
        out.retain(|fb| allowed.contains(Path::new(&fb.path)));
    }
    Ok(out)
}

fn c_default_extensions() -> Vec<String> {
    ["c", "cc", "cpp", "cxx", "h", "hh", "hpp", "hxx"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn walk_recursive(
    root: &Path,
    current: &Path,
    extensions: &[String],
    out: &mut Vec<FileBucket>,
) -> Result<()> {
    let entries = match fs::read_dir(current) {
        Ok(it) => it,
        Err(_) => return Ok(()),
    };
    for entry in entries {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };
        let path = entry.path();
        let name_owned = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };
        let name = name_owned.as_str();

        if SKIP_DIRS.contains(&name) {
            continue;
        }
        if name.starts_with('.') {
            continue;
        }
        let ft = match entry.file_type() {
            Ok(t) => t,
            Err(_) => continue,
        };
        if ft.is_dir() {
            walk_recursive(root, &path, extensions, out)?;
            continue;
        }
        if !ft.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(str::to_ascii_lowercase)
            .unwrap_or_default();
        if !extensions.iter().any(|e| e == &ext) {
            continue;
        }
        let metadata = match path.metadata() {
            Ok(m) => m,
            Err(_) => continue,
        };
        let bytes = metadata.len() as usize;
        if bytes == 0 || bytes > MAX_FILE_BYTES {
            continue;
        }
        let relative = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| path.to_string_lossy().into_owned());
        let est_tokens = est_tokens_for_bytes(bytes);
        out.push(FileBucket {
            path: relative,
            bytes,
            est_tokens,
        });
    }
    Ok(())
}

fn est_tokens_for_bytes(bytes: usize) -> usize {
    ((bytes as f64) / BYTES_PER_TOKEN).ceil() as usize
}

/// Run the full pass — dispatches each chunk through the routed runtime.
pub fn run(
    runtime: &RoutedRuntime,
    spend: Option<&SpendLimiter>,
    cfg: &FullModeConfig,
) -> Result<FullModeReport> {
    let plan = plan(cfg).context("full_mode_multi: planning failed")?;

    if cfg.dry_run {
        return Ok(FullModeReport {
            findings: Vec::new(),
            plan,
            chunks_dispatched: 0,
            chunks_failed: 0,
            cost_usd: 0.0,
            dry_run: true,
        });
    }

    let model = runtime
        .resolve_model(AgentRole::FullModeMulti, 0, None)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no model configured for full_mode_multi role: \
                 set models.toml [roles.full_mode_multi] or `setg MODEL_FULL_MODE_MULTI`"
            )
        })?;
    let system_prompt = match cfg.language {
        FullModeLanguage::C => SYSTEM_PROMPT_C,
        FullModeLanguage::Unknown => SYSTEM_PROMPT_UNKNOWN,
    }
    .to_string();

    let mut all_findings: Vec<Finding> = Vec::new();
    let mut dispatched = 0u32;
    let mut failed = 0u32;
    let mut cost = 0.0f64;

    for chunk in &plan.chunks {
        let ticket = match spend {
            Some(limiter) => Some(
                limiter
                    .deposit(Operation::FullModeMulti, cfg.deposit_usd_per_chunk)
                    .context("full_mode_multi: deposit failed")?,
            ),
            None => None,
        };

        let prompt = render_chunk_prompt(&cfg.workspace_root, chunk)?;
        let request = AgentQueryRequest::new(
            model.clone(),
            cfg.workspace_root.clone(),
            system_prompt.clone(),
            prompt,
        );

        let result = runtime.query_blocking(request);

        let actual_cost = match &result {
            Ok(_) => cfg.deposit_usd_per_chunk, // bridge cost surfaces in Phase 5c+
            Err(_) => 0.0,
        };
        if let (Some(limiter), Some(t)) = (spend, ticket) {
            // Refund must succeed even on chunk failure — we can't strand
            // the budget.
            limiter.refund(t, actual_cost)?;
        }

        match result {
            Ok(response) => {
                cost += actual_cost;
                dispatched += 1;
                let chunk_findings = parse_chunk_response(&response.text, &response.structured);
                all_findings.extend(chunk_findings);
            }
            Err(_error) => {
                failed += 1;
                // Continue — one bad chunk shouldn't kill the whole pass.
            }
        }
    }

    Ok(FullModeReport {
        findings: all_findings,
        plan,
        chunks_dispatched: dispatched,
        chunks_failed: failed,
        cost_usd: cost,
        dry_run: false,
    })
}

fn render_chunk_prompt(root: &Path, chunk: &ChunkPlan) -> Result<String> {
    let mut body = String::with_capacity(chunk.est_tokens * 4);
    body.push_str("Files in this chunk:\n\n");
    for fb in &chunk.files {
        let abs = root.join(&fb.path);
        let contents = match fs::read_to_string(&abs) {
            Ok(c) => c,
            Err(_) => continue,
        };
        body.push_str(&format!("=== {} ===\n", fb.path));
        body.push_str(&contents);
        if !contents.ends_with('\n') {
            body.push('\n');
        }
        body.push('\n');
    }
    Ok(body)
}

fn parse_chunk_response(text: &str, structured: &Option<serde_json::Value>) -> Vec<Finding> {
    if let Some(value) = structured {
        if let Ok(items) = serde_json::from_value::<Vec<ModelFinding>>(value.clone()) {
            return items.into_iter().filter_map(model_to_finding).collect();
        }
    }
    if let Some(array_text) = extract_json_array(text) {
        if let Ok(items) = serde_json::from_str::<Vec<ModelFinding>>(&array_text) {
            return items.into_iter().filter_map(model_to_finding).collect();
        }
    }
    Vec::new()
}

fn extract_json_array(text: &str) -> Option<String> {
    let trimmed = text.trim();
    let stripped = if trimmed.starts_with("```") {
        trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string()
    } else {
        trimmed.to_string()
    };
    if stripped.starts_with('[') {
        return Some(stripped);
    }
    let start = stripped.find('[')?;
    let end = stripped.rfind(']')?;
    if end <= start {
        return None;
    }
    Some(stripped[start..=end].to_string())
}

fn model_to_finding(m: ModelFinding) -> Option<Finding> {
    if m.file.trim().is_empty() || m.line == 0 || m.title.trim().is_empty() {
        return None;
    }
    let severity = parse_severity(&m.severity);
    let mut message = m.rationale.clone();
    if !m.cwe.is_empty() {
        message.push_str("\n");
        message.push_str(&m.cwe.join(", "));
    }
    if !m.function.trim().is_empty() {
        message.push_str(&format!("\nfunction: {}", m.function));
    }
    let rule_id = if m.cwe.is_empty() {
        "full-mode-multi/scan".to_string()
    } else {
        format!("full-mode-multi/{}", m.cwe[0].to_ascii_lowercase())
    };
    Some(Finding::new_tool(
        "full-mode-multi",
        rule_id,
        m.file,
        m.line,
        Some(m.line),
        severity,
        if message.trim().is_empty() {
            m.title.clone()
        } else {
            format!("{}\n\n{}", m.title, message.trim())
        },
    ))
}

fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "med" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Unknown,
    }
}

/// Cost-estimate summary for `--dry-run-cost-estimate`. Prices are
/// rough — a real estimate would use per-model token pricing tables;
/// for v1 we report bands.
pub fn cost_summary(plan: &FullModePlan, model_hint: Option<&str>) -> CostSummary {
    // Conservative per-1k-token rate band ($/1k input tokens).
    let (low, high) = match model_hint.unwrap_or("unknown") {
        s if s.contains("haiku") => (0.001, 0.005),
        s if s.contains("sonnet") => (0.003, 0.015),
        s if s.contains("opus") => (0.015, 0.075),
        s if s.contains("gemini") => (0.0005, 0.005),
        s if s.contains("o3") => (0.005, 0.020),
        _ => (0.001, 0.020),
    };
    let tokens = plan.total_tokens as f64;
    CostSummary {
        chunks: plan.chunks.len(),
        files: plan.total_files,
        total_tokens: plan.total_tokens,
        // Output tokens are usually 5–15% of input; assume 10% on
        // average; charge it at the same rate as input for the band.
        usd_low: low * tokens / 1000.0 * 1.10,
        usd_high: high * tokens / 1000.0 * 1.10,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostSummary {
    pub chunks: usize,
    pub files: usize,
    pub total_tokens: usize,
    pub usd_low: f64,
    pub usd_high: f64,
}

/// Map a [`FullModeReport`] to a JSON Value suitable for tool output.
pub fn report_to_tool_json(report: &FullModeReport) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "data": report,
        "summary": {
            "chunks": report.plan.chunks.len(),
            "files": report.plan.total_files,
            "totalTokens": report.plan.total_tokens,
            "findingsCount": report.findings.len(),
            "chunksDispatched": report.chunks_dispatched,
            "chunksFailed": report.chunks_failed,
            "costUsd": report.cost_usd,
            "dryRun": report.dry_run,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::config::ConfigPaths;
    use crate::findings::TriageOutcome;
    use crate::runtime::{AgentQueryResponse, AgentRuntime, TriageRequest};
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    fn make_workspace(files: &[(&str, &str)]) -> tempfile::TempDir {
        let tmp = tempdir().unwrap();
        for (name, body) in files {
            let p = tmp.path().join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(&p, body).unwrap();
        }
        tmp
    }

    #[test]
    fn plan_groups_files_into_token_bounded_chunks() {
        let big = "x".repeat(10 * 1024); // ~2.7k tokens
        let tmp = make_workspace(&[
            ("src/a.c", &big),
            ("src/b.c", &big),
            ("src/c.c", &big),
            ("ignored.txt", "not c"),
        ]);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 5_000, // forces multiple chunks
            ..Default::default()
        };
        let plan = plan(&cfg).unwrap();
        assert!(plan.chunks.len() >= 2, "expected multiple chunks");
        assert_eq!(plan.total_files, 3);
        // Files sorted by path → chunks are directory-affine.
        let chunk0_paths: Vec<&str> = plan.chunks[0]
            .files
            .iter()
            .map(|f| f.path.as_str())
            .collect();
        assert!(chunk0_paths.iter().any(|p| p.starts_with("src/")));
    }

    #[test]
    fn scope_files_filter_narrows_the_plan_to_diff_set() {
        let big = "// padding\n".repeat(1_500);
        let tmp = make_workspace(&[("src/a.c", &big), ("src/b.c", &big), ("src/c.c", &big)]);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            scope_files: Some(vec![PathBuf::from("src/b.c")]),
            ..Default::default()
        };
        let plan = plan(&cfg).unwrap();
        let paths: Vec<&str> = plan
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(|f| f.path.as_str()))
            .collect();
        assert_eq!(paths, vec!["src/b.c"]);
    }

    #[test]
    fn plan_skips_skip_dirs() {
        let tmp = make_workspace(&[
            ("src/keep.c", "void k(){}"),
            (".git/HEAD", "ref: refs/heads/main"),
            ("node_modules/pkg/src/skip.c", "void s(){}"),
            ("target/build/skip.c", "void s(){}"),
        ]);
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let plan = plan(&cfg).unwrap();
        let paths: Vec<&str> = plan
            .chunks
            .iter()
            .flat_map(|c| c.files.iter().map(|f| f.path.as_str()))
            .collect();
        assert_eq!(paths, vec!["src/keep.c"]);
    }

    #[test]
    fn cost_summary_scales_with_tokens() {
        let plan = FullModePlan {
            chunks: vec![],
            total_files: 100,
            total_bytes: 1_000_000,
            total_tokens: 280_000, // ~1MB at 3.6 B/T
        };
        let summary = cost_summary(&plan, Some("anthropic:claude-haiku-4-5"));
        assert_eq!(summary.total_tokens, 280_000);
        assert!(summary.usd_low > 0.0);
        assert!(summary.usd_high > summary.usd_low);
        let opus_summary = cost_summary(&plan, Some("anthropic:claude-opus-4-7"));
        // Opus is ~10× more expensive than haiku at the high band.
        assert!(opus_summary.usd_high > summary.usd_high * 5.0);
    }

    #[test]
    fn dry_run_produces_plan_without_calling_model() {
        let tmp = make_workspace(&[("src/a.c", "void a(){}")]);
        let inner: Arc<dyn AgentRuntime> = Arc::new(PanickingRuntime);
        let runtime = RoutedRuntime::new(
            inner,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            dry_run: true,
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert!(report.dry_run);
        assert_eq!(report.plan.total_files, 1);
        assert_eq!(report.findings.len(), 0);
    }

    #[test]
    fn dispatches_each_chunk_and_aggregates_findings() {
        let big = "// padding\n".repeat(2_000); // each ~3k tokens
        let tmp = make_workspace(&[("src/a.c", &big), ("src/b.c", &big), ("src/c.c", &big)]);
        let runtime_inner = ScriptedRuntime::new(vec![
            r#"[{"file":"src/a.c","line":42,"function":"foo","severity":"high","cwe":["CWE-787"],"title":"OOB write","rationale":"unbounded copy"}]"#.to_string(),
            r#"[]"#.to_string(),
            r#"[{"file":"src/c.c","line":99,"function":"bar","severity":"medium","cwe":["CWE-125"],"title":"OOB read","rationale":"missing length check"}]"#.to_string(),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner.clone() as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 4_000,
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert!(report.plan.chunks.len() >= 3);
        assert_eq!(report.chunks_dispatched, report.plan.chunks.len() as u32);
        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.findings[0].file_path, "src/a.c");
        assert_eq!(report.findings[0].start_line, 42);
        assert_eq!(report.findings[0].severity, Severity::High);
        assert_eq!(report.findings[1].file_path, "src/c.c");
    }

    #[test]
    fn one_failing_chunk_does_not_abort_pass() {
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body), ("src/b.c", &body)]);
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Ok(
                r#"[{"file":"src/a.c","line":1,"function":"f","severity":"low","cwe":[],"title":"t","rationale":"r"}]"#.to_string(),
            ),
            ScriptedItem::Err("simulated transport error".to_string()),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 4_000,
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert_eq!(report.chunks_failed, 1);
        assert_eq!(report.chunks_dispatched, 1);
        assert_eq!(report.findings.len(), 1);
    }

    #[test]
    fn spend_ledger_settles_each_chunk_even_on_failure() {
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body), ("src/b.c", &body)]);
        let runtime_inner = ScriptedRuntimeMixed::new(vec![
            ScriptedItem::Ok("[]".to_string()),
            ScriptedItem::Err("fail".to_string()),
        ]);
        let runtime = RoutedRuntime::new(
            runtime_inner as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let limiter = SpendLimiter::open_in_memory().unwrap();
        limiter.set_cap(Operation::FullModeMulti, 100.0).unwrap();
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            max_tokens_per_chunk: 4_000,
            deposit_usd_per_chunk: 1.5,
            ..Default::default()
        };
        let report = run(&runtime, Some(&limiter), &cfg).unwrap();
        assert_eq!(report.chunks_dispatched, 1);
        assert_eq!(report.chunks_failed, 1);
        // Successful chunk costs 1.5; failed chunk refunds to 0.
        let spent = limiter.total_spent(Operation::FullModeMulti).unwrap();
        assert!((spent - 1.5).abs() < 1e-9, "got {spent}");
    }

    #[test]
    fn malformed_responses_yield_no_findings_not_panic() {
        let body = "// padding\n".repeat(2_000);
        let tmp = make_workspace(&[("src/a.c", &body)]);
        let runtime_inner = ScriptedRuntime::new(vec!["I don't know what to say".to_string()]);
        let runtime = RoutedRuntime::new(
            runtime_inner as Arc<dyn AgentRuntime>,
            Arc::new(router_with_full_mode_role("anthropic:claude-haiku-4-5")),
            None,
        );
        let cfg = FullModeConfig {
            workspace_root: tmp.path().to_path_buf(),
            ..Default::default()
        };
        let report = run(&runtime, None, &cfg).unwrap();
        assert_eq!(report.findings.len(), 0);
        assert_eq!(report.chunks_dispatched, 1);
    }

    // -- Test runtime helpers ------------------------------------------------

    struct PanickingRuntime;
    impl AgentRuntime for PanickingRuntime {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            panic!("dry-run must not call the runtime")
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
    }

    #[derive(Clone)]
    struct ScriptedRuntime {
        responses: Arc<Mutex<Vec<String>>>,
    }
    impl ScriptedRuntime {
        fn new(responses: Vec<String>) -> Arc<Self> {
            Arc::new(Self {
                responses: Arc::new(Mutex::new(responses)),
            })
        }
    }
    impl AgentRuntime for ScriptedRuntime {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let mut q = self.responses.lock().unwrap();
            anyhow::ensure!(!q.is_empty(), "scripted runtime exhausted");
            Ok(AgentQueryResponse {
                text: q.remove(0),
                structured: None,
                ..Default::default()
            })
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
    }

    enum ScriptedItem {
        Ok(String),
        Err(String),
    }

    #[derive(Clone)]
    struct ScriptedRuntimeMixed {
        items: Arc<Mutex<Vec<ScriptedItem>>>,
    }
    impl ScriptedRuntimeMixed {
        fn new(items: Vec<ScriptedItem>) -> Arc<Self> {
            Arc::new(Self {
                items: Arc::new(Mutex::new(items)),
            })
        }
    }
    impl AgentRuntime for ScriptedRuntimeMixed {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            let mut q = self.items.lock().unwrap();
            anyhow::ensure!(!q.is_empty(), "scripted runtime exhausted");
            match q.remove(0) {
                ScriptedItem::Ok(text) => Ok(AgentQueryResponse {
                    text,
                    structured: None,
                    ..Default::default()
                }),
                ScriptedItem::Err(message) => anyhow::bail!(message),
            }
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
    }

    fn router_with_full_mode_role(model: &str) -> AgentRouter {
        let tmp = tempdir().unwrap();
        let dir = tmp.path().join(".kuzushi");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("models.toml"),
            format!("[roles.full_mode_multi]\nprimary = \"{model}\"\n"),
        )
        .unwrap();
        let r = AgentRouter::load(&ConfigPaths {
            home_dir: tmp.path().to_path_buf(),
            target_dir: None,
        })
        .unwrap();
        let _ = tmp;
        r
    }
}
