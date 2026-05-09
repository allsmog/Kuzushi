use crate::capabilities::full_mode_multi::domain::{ChunkPlan, CostSummary, FullModePlan};
use crate::findings::{Finding, Severity};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;
use std::path::Path;

pub(crate) const SYSTEM_PROMPT_C: &str = r#"You are Kuzushi's whole-codebase scanner. You are seeing
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

pub(crate) const SYSTEM_PROMPT_UNKNOWN: &str = r#"You are Kuzushi's whole-codebase scanner. You are
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
pub(crate) struct ModelFinding {
    #[serde(default)]
    pub(crate) file: String,
    #[serde(default)]
    pub(crate) line: u32,
    #[serde(default)]
    pub(crate) function: String,
    #[serde(default)]
    pub(crate) severity: String,
    #[serde(default)]
    pub(crate) cwe: Vec<String>,
    #[serde(default)]
    pub(crate) title: String,
    #[serde(default)]
    pub(crate) rationale: String,
}

pub(crate) fn render_chunk_prompt(root: &Path, chunk: &ChunkPlan) -> Result<String> {
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

pub(crate) fn parse_chunk_value(value: serde_json::Value) -> Result<Vec<Finding>> {
    let items = serde_json::from_value::<Vec<ModelFinding>>(value)
        .context("full-mode-multi chunk output must be a JSON array of findings")?;
    Ok(items.into_iter().filter_map(model_to_finding).collect())
}

pub(crate) fn full_mode_findings_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "array",
        "items": {
            "type": "object",
            "required": ["rule", "file", "line", "severity", "message"],
            "additionalProperties": true,
            "properties": {
                "rule": {"type": "string"},
                "file": {"type": "string"},
                "line": {"type": "integer"},
                "severity": {"type": "string"},
                "message": {"type": "string"}
            }
        }
    })
}

pub(crate) fn model_to_finding(m: ModelFinding) -> Option<Finding> {
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

pub(crate) fn parse_severity(s: &str) -> Severity {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" | "med" => Severity::Medium,
        "low" => Severity::Low,
        "info" => Severity::Info,
        _ => Severity::Unknown,
    }
}

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
