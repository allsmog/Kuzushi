use super::*;

pub const WHITEBOX_STATIC_AGENT_TOOL_PROFILE: &str = "whitebox-static";

pub const WHITEBOX_STATIC_READ_ONLY_AGENT_TOOLS: &[&str] = &["Read", "Glob", "Grep", "LS"];

pub const WHITEBOX_STATIC_TRIAGE_SYSTEM_PROMPT: &str = r#"You are Kuzushi's agentic SAST scanner operating in whitebox-static mode.
Return only JSON matching:
{"findings":[{"ruleId":"short-rule-id","title":"short title","verdict":"true_positive|false_positive|needs_review","staticProofState":"signal_only|code_cited|source_sink_linked|sanitizer_checked|statically_confirmed|statically_rejected|needs_runtime_evidence","severity":"critical|high|medium|low|info","confidence":"high|medium|low","source":{"kind":"entrypoint|attacker_input|unknown","filePath":"relative/path","startLine":1,"endLine":1,"description":"source evidence"},"sink":{"kind":"sql_query|command_execution|deserialization|file_write|authz_boundary|other","filePath":"relative/path","startLine":1,"endLine":1,"description":"sink evidence"},"path":{"kind":"direct|dataflow|local|unknown","explanation":"static source-to-sink reasoning","steps":[{"filePath":"relative/path","startLine":1,"endLine":1,"description":"flow step"}]},"sanitizerAssessment":{"status":"present|absent|unknown","explanation":"static assessment"},"guardAssessment":{"status":"present|absent|unknown","explanation":"static assessment"},"citations":[{"filePath":"relative/path","startLine":1,"endLine":1,"snippet":"exact source snippet"}],"assumptions":["static assumption"],"missingEvidence":["runtime evidence not assessed"],"triggerNarrative":"static trigger path only","impactNarrative":"potential impact and static evidence limits","recommendedFix":"source-level remediation"}]}.
Use only source-grounded static evidence from the provided repository snippets. If source evidence is insufficient, set verdict to needs_review and staticProofState to needs_runtime_evidence.
Do not include payloads, PoCs, exploit execution instructions, HTTP replay, fuzzing, live target scanning, or runtime exploitability claims.
Never mark a finding execution-confirmed; use statically_confirmed, statically_rejected, or needs_runtime_evidence."#;

pub const WHITEBOX_STATIC_TRIAGE_PROMPT_BLOCK: &str = r#"Whitebox-static triage constraints:
- Static-only analysis: no active exploitation, no HTTP replay, no fuzzing, no live target scanning, no PoC generation, and no PoC execution.
- Every reported claim must cite repository source lines and explain the static source, sink, path, sanitizer assessment, guard assessment, assumptions, and missing evidence.
- Use triggerNarrative and impactNarrative only for static trigger path and potential impact; runtime exploitability is not assessed in whitebox-static mode.
- If citations are missing or stale, prefer needs_runtime_evidence or needs_review instead of statically_confirmed."#;

pub(crate) const WHITEBOX_STATIC_FORBIDDEN_AGENT_TOOLS: &[&str] = &[
    "bash",
    "shell",
    "sh",
    "zsh",
    "fish",
    "powershell",
    "cmd",
    "write",
    "edit",
    "multiedit",
    "patch",
    "applypatch",
    "apply_patch",
    "notebookedit",
];

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AnalysisMode {
    Standard,
    WhiteboxStatic,
}

impl AnalysisMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::WhiteboxStatic => "whitebox-static",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxStaticPolicy {
    pub enabled: bool,
    pub mode: String,
    pub verify: bool,
    pub poc_harness: bool,
    pub poc_execution: bool,
    pub dynamic_analysis: bool,
    pub crypto_behavioral_testing: bool,
    pub patching: bool,
    pub auto_patch: bool,
    pub execution_proof_states: bool,
    pub runtime_exploitability_claims: bool,
    pub disabled: Vec<String>,
}

impl WhiteboxStaticPolicy {
    pub(crate) fn active(disabled: Vec<String>) -> Self {
        Self {
            enabled: true,
            mode: AnalysisMode::WhiteboxStatic.as_str().to_string(),
            verify: false,
            poc_harness: false,
            poc_execution: false,
            dynamic_analysis: false,
            crypto_behavioral_testing: false,
            patching: false,
            auto_patch: false,
            execution_proof_states: false,
            runtime_exploitability_claims: false,
            disabled,
        }
    }

    pub fn to_json(&self) -> Value {
        json!(self)
    }
}
