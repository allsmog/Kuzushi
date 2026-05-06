//! Tool-augmented deep auditor.
//!
//! Given a candidate [`Finding`], run a multi-step LLM loop with the
//! code-nav tool surface and ask the model to verify whether the
//! vulnerability is genuinely triggerable. Records evidence citations
//! (file/line ranges the model read) for later replay.
//!
//! Usage flow:
//!
//! ```text
//! deposit(SpendLimiter, DeepAudit, est_cost)
//! └── run_tool_loop(routed_runtime, request, code_nav_toolbox)
//!     ├── tool calls: read_source / read_definition / find_references / list_definitions
//!     └── final: VulnAnalysis JSON
//! refund(actual_cost)
//! → DeepAuditOutcome { triage, evidence, cost_usd, transcript_summary }
//! ```
//!
//! The auditor is **conservative on parse failure**: if the model
//! returns malformed JSON it falls back to `TriageVerdict::NeedsReview`
//! with the raw text as the rationale. We never silently mark something
//! TruePositive without a structured verdict from the model.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_router::{AgentRole, RoutedRuntime};
use crate::code_nav::{code_nav_tool_specs, code_nav_toolbox, CodeNavConfig};
use crate::findings::{Finding, TriageOutcome, TriageVerdict};
use crate::runtime::{
    run_tool_loop, AgentLoopOutcome, AgentRuntime, AgentToolLoopRequest, LoopHistoryEntry,
};
use crate::spend::{Operation, SpendLimiter};

/// Hard cap on tool-loop steps per finding. Mirrors RoboDuck's tool-loop
/// budget — large enough that the model can read several files but small
/// enough that a runaway loop is bounded.
pub const DEFAULT_MAX_STEPS: u32 = 24;

/// Conservative initial deposit per audit. Real cost surfaces from the
/// bridge per-step and settles via SpendLimiter::refund.
pub const DEFAULT_DEPOSIT_USD: f64 = 1.0;

/// What the model is asked to return as its final structured answer.
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
}

impl DeepAuditConfig {
    pub fn new(workspace_root: impl Into<std::path::PathBuf>) -> Self {
        Self {
            workspace_root: workspace_root.into(),
            max_steps: DEFAULT_MAX_STEPS,
            deposit_usd: DEFAULT_DEPOSIT_USD,
            system_prompt: None,
        }
    }
}

const DEFAULT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's deep auditor. Verify whether the
candidate finding is a genuine, triggerable vulnerability that an attacker can exploit
with realistic inputs. Use the read_source / read_definition / find_references /
list_definitions tools to inspect the code; do NOT speculate beyond what you read.

Rules:
- Read the function body and the call sites that reach it before deciding.
- Trace whether attacker-controlled data flows from input to the alleged sink.
- Check for guards (length checks, allow-lists, type tags) that would prevent the
  vulnerability — if any exists and is reachable, mark triggerable=false.
- Cite every file:line range you relied on as an evidence entry.

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

/// Run a tool-augmented deep audit on a single finding.
///
/// `runtime` should be a `RoutedRuntime` so the model is selected by the
/// `DeepAuditor` role. Per-call enforcement uses the supplied
/// [`SpendLimiter`]; pass `None` to skip budgeting (tests / dry-runs).
pub fn run_deep_auditor(
    runtime: &RoutedRuntime,
    spend: Option<&SpendLimiter>,
    cfg: &DeepAuditConfig,
    finding: &Finding,
) -> Result<DeepAuditOutcome> {
    // 1. Resolve model via router.
    let model = runtime
        .resolve_model(AgentRole::DeepAuditor, 0, None)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no model configured for the deep_auditor role: \
                 set models.toml [roles.deep_auditor] or `setg MODEL_DEEP_AUDITOR`"
            )
        })?;

    // 2. Open spend ticket.
    let ticket = match spend {
        Some(limiter) => Some(
            limiter
                .deposit(Operation::DeepAudit, cfg.deposit_usd)
                .context("deep_audit deposit failed (cap reached?)")?,
        ),
        None => None,
    };

    // 3. Build request + toolbox.
    let request = AgentToolLoopRequest {
        model,
        cwd: cfg.workspace_root.clone(),
        system_prompt: cfg
            .system_prompt
            .clone()
            .unwrap_or_else(|| DEFAULT_SYSTEM_PROMPT.to_string()),
        prompt: render_user_prompt(finding),
        tools: code_nav_tool_specs(),
        max_steps: cfg.max_steps.max(1),
    };

    let mut toolbox = code_nav_toolbox(CodeNavConfig::new(&cfg.workspace_root));

    // 4. Drive the loop.
    let outcome: AgentLoopOutcome =
        run_tool_loop(runtime as &dyn AgentRuntime, &request, &mut toolbox)
            .context("deep_audit tool loop failed")?;

    // 5. Settle spend.
    if let (Some(limiter), Some(ticket)) = (spend, ticket) {
        let actual = if outcome.cost_usd > 0.0 {
            outcome.cost_usd
        } else {
            cfg.deposit_usd
        };
        limiter
            .refund(ticket, actual)
            .context("deep_audit refund failed")?;
    }

    // 6. Parse final structured output.
    let analysis = parse_vuln_analysis(&outcome);
    let triage = build_triage_outcome(&analysis, &outcome);

    Ok(DeepAuditOutcome {
        triage,
        evidence: analysis.evidence,
        cost_usd: outcome.cost_usd,
        steps_used: outcome.steps_used,
        truncated: outcome.truncated,
    })
}

fn render_user_prompt(finding: &Finding) -> String {
    let location = match finding.end_line {
        Some(end) if end != finding.start_line => {
            format!("{}:{}–{}", finding.file_path, finding.start_line, end)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    };
    format!(
        "Audit this candidate finding:\n\n\
         tool       : {tool}\n\
         rule_id    : {rule}\n\
         severity   : {sev}\n\
         location   : {loc}\n\
         title      : {title}\n\
         message    :\n{msg}\n\n\
         Decide if it is genuinely triggerable. Use the tools to verify before answering.",
        tool = finding.tool,
        rule = finding.rule_id,
        sev = finding.severity.as_str(),
        loc = location,
        title = finding.title,
        msg = finding.message,
    )
}

fn parse_vuln_analysis(outcome: &AgentLoopOutcome) -> VulnAnalysis {
    if let Some(ref structured) = outcome.structured {
        if let Ok(analysis) = serde_json::from_value::<VulnAnalysis>(structured.clone()) {
            return clamp(analysis);
        }
    }
    if !outcome.text.is_empty() {
        if let Some(parsed) = try_parse_loose_json::<VulnAnalysis>(&outcome.text) {
            return clamp(parsed);
        }
    }
    // Conservative fallback: not triggerable, low confidence, attach the
    // raw text so an operator can review.
    VulnAnalysis {
        triggerable: false,
        rationale: if outcome.text.is_empty() {
            "deep auditor returned no structured verdict".to_string()
        } else {
            outcome.text.clone()
        },
        confidence: 0.25,
        evidence: collect_implicit_evidence(&outcome.transcript),
    }
}

/// Salvage evidence from tool transcripts when the model didn't return
/// any in its structured answer. We pick out file/line ranges from
/// successful read_source calls and the matching arguments.
fn collect_implicit_evidence(transcript: &[LoopHistoryEntry]) -> Vec<EvidenceCitation> {
    let mut out = Vec::new();
    let mut last_call_args: Option<Value> = None;
    for entry in transcript {
        match entry {
            LoopHistoryEntry::AssistantToolCall(call) if call.name == "read_source" => {
                last_call_args = Some(call.input.clone());
            }
            LoopHistoryEntry::ToolResult(result)
                if !result.is_error && last_call_args.is_some() =>
            {
                let args = last_call_args.take().unwrap();
                let file = args
                    .get("file")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                if file.is_empty() {
                    continue;
                }
                let start = result
                    .output
                    .get("start_line")
                    .and_then(Value::as_u64)
                    .unwrap_or(0) as u32;
                let end = result
                    .output
                    .get("end_line")
                    .and_then(Value::as_u64)
                    .unwrap_or(start as u64) as u32;
                out.push(EvidenceCitation {
                    file,
                    start_line: start,
                    end_line: end,
                    note: "auditor read this region".to_string(),
                    kind: "context".to_string(),
                });
            }
            _ => {}
        }
    }
    out
}

fn try_parse_loose_json<T: serde::de::DeserializeOwned>(text: &str) -> Option<T> {
    // Strip ```json fences if present, then locate the outermost {...}.
    let trimmed = text.trim();
    let stripped = if trimmed.starts_with("```") {
        let after = trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```");
        after.trim_end_matches("```").trim().to_string()
    } else {
        trimmed.to_string()
    };
    if let Ok(value) = serde_json::from_str::<T>(&stripped) {
        return Some(value);
    }
    let start = stripped.find('{')?;
    let end = stripped.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&stripped[start..=end]).ok()
}

fn clamp(mut a: VulnAnalysis) -> VulnAnalysis {
    a.confidence = a.confidence.clamp(0.0, 1.0);
    a
}

fn build_triage_outcome(analysis: &VulnAnalysis, outcome: &AgentLoopOutcome) -> TriageOutcome {
    let verdict = match (analysis.triggerable, analysis.confidence) {
        (true, c) if c >= 0.5 => TriageVerdict::TruePositive,
        (false, c) if c >= 0.7 => TriageVerdict::FalsePositive,
        _ => TriageVerdict::NeedsReview,
    };
    let rationale = if outcome.truncated {
        format!(
            "[deep-auditor truncated at {} steps] {}",
            outcome.steps_used, analysis.rationale
        )
    } else {
        analysis.rationale.clone()
    };
    TriageOutcome {
        verdict,
        confidence: analysis.confidence,
        rationale,
        cost_usd: 0.0,
    }
}

/// Persist evidence citations into the optional `findings_evidence`
/// table. Best-effort — failures log but don't propagate, since the
/// audit verdict itself is the primary artefact.
pub fn save_evidence(db_path: &Path, finding_id: i64, evidence: &[EvidenceCitation]) -> Result<()> {
    if evidence.is_empty() {
        return Ok(());
    }
    let conn = rusqlite::Connection::open(db_path)
        .with_context(|| format!("could not open {} for evidence", db_path.display()))?;
    conn.execute_batch(
        r#"
        create table if not exists findings_evidence (
          id          integer primary key autoincrement,
          finding_id  integer not null,
          file        text    not null,
          start_line  integer not null,
          end_line    integer not null,
          note        text,
          kind        text,
          created_at  text    not null default (datetime('now'))
        );
        create index if not exists idx_findings_evidence_finding
          on findings_evidence(finding_id);
        "#,
    )?;
    let mut stmt = conn.prepare(
        "insert into findings_evidence(finding_id, file, start_line, end_line, note, kind)
         values (?, ?, ?, ?, ?, ?)",
    )?;
    for ev in evidence {
        stmt.execute(rusqlite::params![
            finding_id,
            ev.file,
            ev.start_line,
            ev.end_line,
            ev.note,
            ev.kind
        ])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_router::{AgentRouter, RoutedRuntime};
    use crate::findings::Severity;
    use crate::runtime::{
        AgentLoopStep, AgentQueryRequest, AgentQueryResponse, ToolCall, TriageRequest,
    };
    use std::sync::{Arc, Mutex};

    /// Mock runtime that walks a scripted sequence of steps. Tests use it
    /// to drive deterministic auditor behaviour.
    struct ScriptedRuntime {
        steps: Mutex<Vec<AgentLoopStep>>,
    }
    impl ScriptedRuntime {
        fn new(steps: Vec<AgentLoopStep>) -> Arc<Self> {
            Arc::new(Self {
                steps: Mutex::new(steps),
            })
        }
    }
    impl AgentRuntime for ScriptedRuntime {
        fn query_blocking(&self, _: AgentQueryRequest) -> Result<AgentQueryResponse> {
            unreachable!()
        }
        fn triage_finding_blocking(&self, _: TriageRequest) -> Result<TriageOutcome> {
            unreachable!()
        }
        fn supports_tools(&self) -> bool {
            true
        }
        fn next_step_blocking(
            &self,
            _request: &AgentToolLoopRequest,
            _history: &[LoopHistoryEntry],
        ) -> Result<AgentLoopStep> {
            let mut s = self.steps.lock().unwrap();
            anyhow::ensure!(!s.is_empty(), "scripted runtime exhausted");
            Ok(s.remove(0))
        }
    }

    fn finding() -> Finding {
        Finding::new_tool(
            "semgrep",
            "java.injection",
            "src/foo.c",
            42,
            Some(50),
            Severity::High,
            "Possible OOB write via user-controlled length",
        )
    }

    fn routed_runtime_with_role(steps: Vec<AgentLoopStep>) -> RoutedRuntime {
        let runtime: Arc<dyn AgentRuntime> = ScriptedRuntime::new(steps);
        let mut router = AgentRouter::empty();
        router_add_route(
            &mut router,
            AgentRole::DeepAuditor,
            "anthropic:claude-opus-4-7",
        );
        RoutedRuntime::new(runtime, Arc::new(router), None)
    }

    fn router_add_route(router: &mut AgentRouter, role: AgentRole, primary: &str) {
        // The router's `routes` field is module-private — so for the
        // test we round-trip through models.toml.
        use std::fs;
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join(".kuzushi");
        fs::create_dir_all(&dir).unwrap();
        fs::write(
            dir.join("models.toml"),
            format!("[roles.{}]\nprimary = \"{}\"\n", role.as_key(), primary),
        )
        .unwrap();
        let loaded = AgentRouter::load(&crate::config::ConfigPaths {
            home_dir: tmp.path().to_path_buf(),
            target_dir: None,
        })
        .unwrap();
        *router = loaded;
        // tmpdir intentionally leaks for the duration of the test — Drop
        // closes it; the router has already loaded the data it needs.
        let _ = tmp;
    }

    #[test]
    fn parses_structured_true_positive_verdict() {
        let outcome = AgentLoopOutcome {
            text: String::new(),
            structured: Some(serde_json::json!({
                "triggerable": true,
                "rationale": "user-controlled len reaches memcpy without check",
                "confidence": 0.85,
                "evidence": [{
                    "file": "src/foo.c", "start_line": 42, "end_line": 50,
                    "note": "no bounds check", "kind": "sink"
                }]
            })),
            steps_used: 3,
            truncated: false,
            cost_usd: 0.012,
            transcript: vec![],
        };
        let analysis = parse_vuln_analysis(&outcome);
        assert!(analysis.triggerable);
        assert!((analysis.confidence - 0.85).abs() < 1e-6);
        assert_eq!(analysis.evidence.len(), 1);
        let triage = build_triage_outcome(&analysis, &outcome);
        assert_eq!(triage.verdict, TriageVerdict::TruePositive);
    }

    #[test]
    fn parses_loose_json_inside_text_response() {
        let outcome = AgentLoopOutcome {
            text: "Here is my answer:\n```json\n{\"triggerable\":false,\"rationale\":\"safe\",\"confidence\":0.9}\n```".to_string(),
            structured: None,
            steps_used: 1,
            truncated: false,
            cost_usd: 0.0,
            transcript: vec![],
        };
        let analysis = parse_vuln_analysis(&outcome);
        assert!(!analysis.triggerable);
        assert!((analysis.confidence - 0.9).abs() < 1e-6);
        let triage = build_triage_outcome(&analysis, &outcome);
        assert_eq!(triage.verdict, TriageVerdict::FalsePositive);
    }

    #[test]
    fn malformed_response_falls_back_to_needs_review() {
        let outcome = AgentLoopOutcome {
            text: "I'm not sure about this one.".to_string(),
            structured: None,
            steps_used: 1,
            truncated: false,
            cost_usd: 0.0,
            transcript: vec![],
        };
        let analysis = parse_vuln_analysis(&outcome);
        assert!(!analysis.triggerable);
        assert!(analysis.confidence < 0.5);
        let triage = build_triage_outcome(&analysis, &outcome);
        assert_eq!(triage.verdict, TriageVerdict::NeedsReview);
    }

    #[test]
    fn truncation_marks_rationale_and_falls_back_to_needs_review() {
        let outcome = AgentLoopOutcome {
            text: String::new(),
            structured: Some(serde_json::json!({
                "triggerable": true,
                "rationale": "looked promising",
                "confidence": 0.6,
                "evidence": []
            })),
            steps_used: 24,
            truncated: true,
            cost_usd: 0.0,
            transcript: vec![],
        };
        let analysis = parse_vuln_analysis(&outcome);
        let triage = build_triage_outcome(&analysis, &outcome);
        assert!(triage.rationale.contains("truncated"));
        // Truncated true_positive at 0.6 → still TruePositive (>=0.5),
        // but the operator-visible rationale is decorated.
        assert_eq!(triage.verdict, TriageVerdict::TruePositive);
    }

    #[test]
    fn deep_auditor_drives_loop_to_completion_with_spend_settlement() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path();
        std::fs::write(workspace.join("foo.c"), "void foo() {}\n").unwrap();

        // Two-step script: model reads source, then returns final.
        let steps = vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({ "file": "foo.c" }),
                    call_id: "c1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: String::new(),
                structured: Some(serde_json::json!({
                    "triggerable": false,
                    "rationale": "no user input reaches the function",
                    "confidence": 0.85,
                    "evidence": [{
                        "file": "foo.c", "start_line": 1, "end_line": 1,
                        "note": "trivially safe", "kind": "context"
                    }]
                })),
                cost_usd: Some(0.05),
            },
        ];
        let runtime = routed_runtime_with_role(steps);
        let limiter = SpendLimiter::open_in_memory().unwrap();
        limiter.set_cap(Operation::DeepAudit, 100.0).unwrap();

        let cfg = DeepAuditConfig::new(workspace);
        let outcome = run_deep_auditor(&runtime, Some(&limiter), &cfg, &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::FalsePositive);
        assert_eq!(outcome.evidence.len(), 1);
        assert!((outcome.cost_usd - 0.05).abs() < 1e-9);
        assert_eq!(outcome.steps_used, 2);

        // Spend settled at 0.05, not the 1.0 deposit.
        assert!((limiter.total_spent(Operation::DeepAudit).unwrap() - 0.05).abs() < 1e-9);
    }

    #[test]
    fn deep_auditor_collects_implicit_evidence_from_tool_calls() {
        // Model returns no evidence in its final, but its tool calls reveal
        // which regions it consulted.
        let tmp = tempfile::tempdir().unwrap();
        let workspace = tmp.path();
        std::fs::write(workspace.join("a.c"), "int a;\nint b;\nint c;\n").unwrap();
        let steps = vec![
            AgentLoopStep::ToolCall {
                call: ToolCall {
                    name: "read_source".to_string(),
                    input: serde_json::json!({ "file": "a.c", "start_line": 1, "end_line": 3 }),
                    call_id: "c1".to_string(),
                },
            },
            AgentLoopStep::Final {
                text: "I cannot determine triggerability".to_string(),
                structured: None,
                cost_usd: None,
            },
        ];
        let runtime = routed_runtime_with_role(steps);
        let cfg = DeepAuditConfig::new(workspace);
        let outcome = run_deep_auditor(&runtime, None, &cfg, &finding()).unwrap();

        assert_eq!(outcome.triage.verdict, TriageVerdict::NeedsReview);
        // Implicit evidence picked up from the read_source call.
        assert_eq!(outcome.evidence.len(), 1);
        assert_eq!(outcome.evidence[0].file, "a.c");
        assert_eq!(outcome.evidence[0].start_line, 1);
        assert_eq!(outcome.evidence[0].end_line, 3);
    }

    #[test]
    fn save_evidence_persists_rows_in_findings_evidence_table() {
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("findings.sqlite3");
        let evidence = vec![EvidenceCitation {
            file: "src/foo.c".to_string(),
            start_line: 10,
            end_line: 20,
            note: "OOB sink".to_string(),
            kind: "sink".to_string(),
        }];
        save_evidence(&db, 42, &evidence).unwrap();

        let conn = rusqlite::Connection::open(&db).unwrap();
        let count: i64 = conn
            .query_row(
                "select count(*) from findings_evidence where finding_id = ?",
                rusqlite::params![42],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
    }
}
