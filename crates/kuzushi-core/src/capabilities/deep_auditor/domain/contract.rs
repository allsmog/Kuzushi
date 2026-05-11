use crate::findings::TriageOutcome;
use serde::{Deserialize, Serialize};

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

Method (target 3-6 tool calls, max 12):
1. Read the function body containing the alleged sink.
2. Read the surrounding caller(s) — use find_references on the function name to
   locate dispatchers / entry points. A common false-positive class is a missing
   *local* upper-bound check that is actually enforced by a centralized validator
   one or two frames up the stack. Always check for this before deciding.
3. Trace attacker-controlled values from the entry point down to the sink, naming
   the source and any guards you encounter.
4. As soon as you can answer "is the alleged primitive reachable with attacker
   inputs that bypass every guard you saw?", STOP reading and emit the verdict.

Hard rule: you have a tool budget. Aim to emit the verdict between steps 4 and
8. Reading more than 10 regions of source is almost always wasted budget — the
verdict should be obvious well before then. If you find yourself wanting to read
"just one more file" past step 8, emit your current best verdict instead and let
the human reviewer drill further.

Return ONLY a JSON object matching this schema as your final message (no tool
call, just the JSON):

{
  "triggerable": bool,
  "rationale": "one or two sentences explaining the verdict, naming the guard or
                the missing guard, and citing file:line",
  "confidence": 0.0..=1.0,
  "evidence": [
    {"file": "path/relative/to/root.c", "start_line": int, "end_line": int,
     "note": "short evidence note", "kind": "source|sink|guard|context"}
  ]
}

Confidence calibration:
- 0.85-1.0: traced a specific reachable input → unguarded sink, or found a clear
  centralized validator that defeats every attacker-controlled value.
- 0.5-0.84: pattern is real and one path is unguarded, but you couldn't confirm
  reachability end-to-end.
- 0.0-0.49: ran out of budget or signals are mixed — Kuzushi surfaces as
  needs_review."#;
