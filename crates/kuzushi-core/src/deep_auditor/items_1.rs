use super::prelude::*;
use super::*;

pub const DEFAULT_MAX_STEPS: u32 = 24;

pub const DEFAULT_DEPOSIT_USD: f64 = 1.0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnAnalysis {
    pub triggerable: bool,
    /// Human-readable rationale, present whether triggerable or not.
    pub rationale: String,
    /// 0.0..=1.0 confidence the verdict is correct.
    #[serde(default)]
    pub confidence: f32,
    /// Evidence citations the model relied on.
    #[serde(default)]
    pub evidence: Vec<EvidenceCitation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceCitation {
    pub file: String,
    pub start_line: u32,
    pub end_line: u32,
    /// Free-form note, e.g. "user input enters here", "missing bounds check".
    #[serde(default)]
    pub note: String,
    /// Optional kind tag: "source" | "sink" | "guard" | "context".
    #[serde(default)]
    pub kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeepAuditOutcome {
    pub triage: TriageOutcome,
    pub evidence: Vec<EvidenceCitation>,
    pub cost_usd: f64,
    pub steps_used: u32,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct DeepAuditConfig {
    pub workspace_root: std::path::PathBuf,
    pub max_steps: u32,
    pub deposit_usd: f64,
    pub system_prompt: Option<String>,
    /// Include whitebox-static narrative, registry, and evidence-graph context in the prompt.
    pub include_static_evidence: bool,
}

impl DeepAuditConfig {
    pub fn new(workspace_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            max_steps: DEFAULT_MAX_STEPS,
            deposit_usd: DEFAULT_DEPOSIT_USD,
            system_prompt: None,
            include_static_evidence: true,
        }
    }
}

pub(crate) const DEFAULT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's deep auditor. Verify whether the
candidate finding is a genuine, triggerable vulnerability that an attacker can exploit
with realistic inputs. Use the read_source / read_definition / find_references /
list_definitions tools to inspect the code; do NOT speculate beyond what you read.

Rules:
- Read the function body and the call sites that reach it before deciding.
- Trace whether attacker-controlled data flows from input to the alleged sink.
- Check for guards (length checks, allow-lists, type tags) that would prevent the
  vulnerability — if any exists and is reachable, mark triggerable=false.
- Cite every file:line range you relied on as an evidence entry.
- If a "Pre-populated Static Evidence" section is present, treat registry-tagged
  sources, sinks, sanitizers, and guards as starting points to verify in source.

Return ONLY a JSON object matching:

{
  "triggerable": bool,
  "rationale": "one or two sentences explaining the verdict",
  "confidence": 0.0..=1.0,
  "evidence": [
    {"file": "path/relative/to/root.c", "start_line": int, "end_line": int,
     "note": "short evidence note", "kind": "source|sink|guard|context"}

  ]
}

If you are uncertain after exhausting your tool budget, return triggerable=false with
confidence below 0.5 — Kuzushi will surface that as needs_review."#;
