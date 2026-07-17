use crate::capabilities::full_mode_multi::domain::{
    ChunkPlan, CostSummary, FullModePlan, MAX_FILE_BYTES,
};
use crate::findings::{Finding, Severity};
use anyhow::{Context, Result};
use serde::Deserialize;
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
        let contents = match crate::bounded_file::read_utf8_text(
            &abs,
            fb.bytes.min(MAX_FILE_BYTES),
        ) {
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
    // Keep the schema aligned with the prompt and `ModelFinding`. The previous
    // shape (`rule`/`message`) made the structured-output channel reject the
    // shape the prompt actually requests; Haiku ends up either repairing into
    // unusable empty fields or returning [], both of which deserialise to 0
    // findings via `model_to_finding`'s required-field filter.
    serde_json::json!({
        "type": "array",
        "items": {
            "type": "object",
            "required": ["file", "line", "severity", "title"],
            "additionalProperties": true,
            "properties": {
                "file": {"type": "string"},
                "line": {"type": "integer", "minimum": 1},
                "function": {"type": "string"},
                "severity": {
                    "type": "string",
                    "enum": ["low", "medium", "high", "critical"]
                },
                "cwe": {
                    "type": "array",
                    "items": {"type": "string"}
                },
                "title": {"type": "string"},
                "rationale": {"type": "string"}
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
    Severity::from_label(s)
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

#[cfg(test)]
mod tests {
    use super::{full_mode_findings_schema, parse_chunk_value, SYSTEM_PROMPT_C};
    use crate::findings::Severity;

    #[test]
    fn schema_required_fields_match_prompt_and_deserializer() {
        // Regression: the schema previously required `rule` + `message`, but
        // the prompt asks for `file`/`line`/`severity`/`title`/... and the
        // deserialiser (ModelFinding) uses those names. The mismatch made
        // Anthropic's structured-output channel either reject the response
        // or coerce it into a shape where every finding had empty file/title
        // and was silently dropped by `model_to_finding`'s required-field
        // filter — so every Haiku full-mode chunk reported 0 findings even
        // when the input had obvious bugs.
        let schema = full_mode_findings_schema();
        let required: Vec<String> = schema["items"]["required"]
            .as_array()
            .expect("schema items.required must be an array")
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        assert!(required.iter().any(|f| f == "file"));
        assert!(required.iter().any(|f| f == "line"));
        assert!(required.iter().any(|f| f == "severity"));
        assert!(required.iter().any(|f| f == "title"));
        assert!(!required.iter().any(|f| f == "rule"));
        assert!(!required.iter().any(|f| f == "message"));

        for field in [
            "file",
            "line",
            "function",
            "severity",
            "cwe",
            "title",
            "rationale",
        ] {
            assert!(
                SYSTEM_PROMPT_C.contains(field),
                "SYSTEM_PROMPT_C drifted: missing {field:?}",
            );
        }
    }

    #[test]
    fn parse_chunk_value_round_trips_prompt_shape() {
        let raw = serde_json::json!([
            {
                "file": "crypto/algif_aead.c",
                "line": 123,
                "function": "aead_recvmsg",
                "severity": "critical",
                "cwe": ["CWE-787"],
                "title": "OOB write via chained AEAD tag scatterlist",
                "rationale": "authencesn writes seqno_lo at dst[assoclen+cryptlen] into a sg_chain'd tag page sourced from splice."
            }
        ]);
        let findings = parse_chunk_value(raw).expect("parse should succeed for prompt shape");
        assert_eq!(findings.len(), 1, "prompt-shaped finding must survive");
        let f = &findings[0];
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.file_path, "crypto/algif_aead.c");
        assert_eq!(f.start_line, 123);
    }
}
