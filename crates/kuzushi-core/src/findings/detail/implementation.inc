use serde::Serialize;

use super::{
    Finding, PatchResult, PatchStatus, PersistedProofVerdict, PersistedVerification,
    StaticProofState, TriageVerdict, VulnSource,
};

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingNextAction {
    Validate,
    Suppress,
    Patch,
    Review,
}

impl FindingNextAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::Suppress => "suppress",
            Self::Patch => "patch",
            Self::Review => "review",
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ProofLadderState {
    pub stage: String,
    pub label: String,
    pub reason: String,
    pub next_step: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FindingDetailReport {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    pub finding: Finding,
    pub proof_state: String,
    pub runtime_validation: String,
    pub proof_ladder: ProofLadderState,
    pub next_action: FindingNextAction,
    pub patch_results: Vec<PatchResult>,
}

impl FindingDetailReport {
    pub fn new(alias: Option<String>, finding: Finding, patch_results: Vec<PatchResult>) -> Self {
        let proof_state = proof_state_label(finding.static_proof_state).to_string();
        let runtime_validation = runtime_validation_label(finding.verification.as_ref());
        let next_action = next_action(&finding, patch_results.first());
        let proof_ladder = proof_ladder_state(&finding, patch_results.first());
        Self {
            alias,
            finding,
            proof_state,
            runtime_validation,
            proof_ladder,
            next_action,
            patch_results,
        }
    }

    pub fn output(&self) -> String {
        let finding = &self.finding;
        let mut lines = Vec::new();
        lines.push(match &self.alias {
            Some(alias) => format!("Finding {alias}"),
            None => "Finding".to_string(),
        });
        if let Some(alias) = &self.alias {
            lines.push(format!("Alias: {alias}"));
        }
        lines.push(format!("Fingerprint: {}", finding.fingerprint));
        lines.push(format!("Title: {}", finding.title));
        lines.push(format!("Severity: {}", finding.severity.as_str()));
        lines.push(format!("Check state: {}", check_state(finding)));
        lines.push(format!("Location: {}", location(finding)));
        lines.push(format!("Tool: {}", finding.tool));
        lines.push(format!("Source: {}", source_label(finding)));
        lines.push(format!("Rule: {}", finding.rule_id));
        lines.push(String::new());
        lines.push("Message:".to_string());
        lines.extend(indent_lines(&finding.message));
        lines.push(String::new());
        lines.push(format!("Proof state: {}", self.proof_state));
        lines.push(format!("Runtime validation: {}", self.runtime_validation));
        lines.push(format!(
            "Proof ladder: {} - {}",
            self.proof_ladder.stage, self.proof_ladder.reason
        ));
        lines.push(format!("Next proof step: {}", self.proof_ladder.next_step));
        if let Some(triage) = &finding.triage {
            lines.push(String::new());
            lines.push("Triage:".to_string());
            lines.push(format!("  Verdict: {}", triage.verdict.as_str()));
            lines.push(format!("  Confidence: {:.2}", triage.confidence));
            lines.push(format!("  Rationale: {}", triage.rationale));
            lines.push(format!("  Cost USD: {:.4}", triage.cost_usd));
        }
        if let Some(verification) = &finding.verification {
            lines.push(String::new());
            lines.push("Verification:".to_string());
            lines.push(format!(
                "  Verdict: {}",
                verification.proof_verdict.as_str()
            ));
            lines.push(format!("  Proof level: {}", verification.proof_level));
            lines.push(format!("  Backend: {}", verification.backend.as_str()));
            if let Some(language) = &verification.language {
                lines.push(format!("  Language: {language}"));
            }
            if let Some(harness_path) = &verification.harness_path {
                lines.push(format!("  Harness: {harness_path}"));
            }
            if let Some(crash_evidence) = &verification.crash_evidence {
                lines.push(format!("  Evidence: {crash_evidence}"));
            }
            if !verification.notes.is_empty() {
                lines.push(format!("  Notes: {}", verification.notes.join("; ")));
            }
        }
        lines.push(String::new());
        lines.push("Patch result:".to_string());
        if let Some(patch) = self.patch_results.first() {
            lines.push(format!("  Status: {}", patch.status.as_str()));
            lines.push(format!("  Iterations: {}", patch.iterations));
            if let Some(test_command) = &patch.test_command {
                lines.push(format!("  Test command: {test_command}"));
            }
            if let Some(worktree_path) = &patch.worktree_path {
                lines.push(format!("  Worktree: {worktree_path}"));
            }
        } else {
            lines.push("  not recorded".to_string());
        }
        lines.push(String::new());
        lines.push(format!("Next action: {}", self.next_action.as_str()));
        lines.join("\n")
    }
}

pub fn proof_state_label(state: Option<StaticProofState>) -> &'static str {
    match state {
        None => "not recorded",
        Some(StaticProofState::SignalOnly) => {
            "signal_only - Scanner signal only; source-grounded evidence is not recorded"
        }
        Some(StaticProofState::CodeCited) => {
            "code_cited - Source-grounded code evidence cited, not empirically validated"
        }
        Some(StaticProofState::SourceSinkLinked) => {
            "source_sink_linked - Source and sink are linked in static evidence, not empirically validated"
        }
        Some(StaticProofState::SanitizerChecked) => {
            "sanitizer_checked - Static path includes sanitizer checks, not empirically validated"
        }
        Some(StaticProofState::StaticallyConfirmed) => {
            "statically_confirmed - Source-grounded and statically confirmed, not empirically validated"
        }
        Some(StaticProofState::StaticallyRejected) => {
            "statically_rejected - Static evidence rejected this as vulnerable"
        }
        Some(StaticProofState::NeedsRuntimeEvidence) => {
            "needs_runtime_evidence - Static evidence needs runtime validation"
        }
    }
}

pub fn runtime_validation_label(verification: Option<&PersistedVerification>) -> String {
    let Some(verification) = verification else {
        return "not attempted".to_string();
    };
    match verification.proof_verdict {
        PersistedProofVerdict::Exploited => {
            format!(
                "execution_confirmed - Empirically confirmed at proof level {}",
                verification.proof_level
            )
        }
        PersistedProofVerdict::NotReproduced => {
            "execution_attempted - Runtime validation attempted; exploit was not reproduced"
                .to_string()
        }
        PersistedProofVerdict::HarnessFailedToBuild => {
            "execution_rejected - Validation harness failed to build".to_string()
        }
        PersistedProofVerdict::InfrastructureError => {
            "execution_rejected - Runtime validation was blocked by infrastructure".to_string()
        }
        PersistedProofVerdict::LanguageUnsupportedYet => {
            "execution_rejected - Runtime validation does not support this language yet".to_string()
        }
        PersistedProofVerdict::InsufficientFindingDetail => {
            "execution_rejected - Finding lacks enough detail for runtime validation".to_string()
        }
    }
}

fn next_action(finding: &Finding, latest_patch: Option<&PatchResult>) -> FindingNextAction {
    if matches!(
        latest_patch.map(|patch| patch.status),
        Some(PatchStatus::Sound | PatchStatus::Verified)
    ) {
        return FindingNextAction::Review;
    }
    if matches!(
        finding.verification.as_ref().map(|v| v.proof_verdict),
        Some(PersistedProofVerdict::Exploited)
    ) {
        return FindingNextAction::Patch;
    }
    if matches!(
        finding.triage.as_ref().map(|triage| triage.verdict),
        Some(TriageVerdict::FalsePositive | TriageVerdict::ByDesign)
    ) || matches!(
        finding.static_proof_state,
        Some(StaticProofState::StaticallyRejected)
    ) {
        return FindingNextAction::Suppress;
    }
    if matches!(
        finding.static_proof_state,
        Some(StaticProofState::NeedsRuntimeEvidence | StaticProofState::SourceSinkLinked)
    ) || finding.verification.is_none()
    {
        return FindingNextAction::Validate;
    }
    FindingNextAction::Review
}

fn check_state(finding: &Finding) -> &'static str {
    finding
        .triage
        .as_ref()
        .map(|triage| triage.verdict.as_str())
        .unwrap_or("needs_review")
}

fn location(finding: &Finding) -> String {
    match finding.end_line {
        Some(end) if end != finding.start_line => {
            format!("{}:{}-{}", finding.file_path, finding.start_line, end)
        }
        _ => format!("{}:{}", finding.file_path, finding.start_line),
    }
}

fn source_label(finding: &Finding) -> &'static str {
    finding
        .vuln_source
        .unwrap_or_else(|| VulnSource::from_tool(&finding.tool))
        .as_str()
}

pub fn proof_ladder_state(
    finding: &Finding,
    latest_patch: Option<&PatchResult>,
) -> ProofLadderState {
    if matches!(
        latest_patch.map(|patch| patch.status),
        Some(PatchStatus::Sound | PatchStatus::Verified)
    ) {
        return proof_ladder(
            "patched",
            "patched - remediation evidence recorded",
            "latest patch result is sound or verified",
            "review the PR comment and keep post-patch validation attached",
        );
    }
    if matches!(
        finding.verification.as_ref().map(|v| v.proof_verdict),
        Some(PersistedProofVerdict::Exploited)
    ) {
        return proof_ladder(
            "validated",
            "validated - empirical runtime evidence recorded",
            "runtime validation reproduced exploitability",
            "patch the finding and re-run validation",
        );
    }
    if matches!(
        finding.static_proof_state,
        Some(StaticProofState::SourceSinkLinked | StaticProofState::SanitizerChecked)
    ) {
        return proof_ladder(
            "path_linked",
            "path-linked - static source/sink evidence recorded",
            "static evidence links a source to a sink or sanitizer assessment",
            "run verify:finding or attach runtime evidence",
        );
    }
    if matches!(
        finding.static_proof_state,
        Some(StaticProofState::CodeCited | StaticProofState::StaticallyConfirmed)
    ) {
        return proof_ladder(
            "source_grounded",
            "source-grounded - code evidence recorded",
            "the finding cites source evidence but not a validated path",
            "collect source/sink path evidence or validate runtime behavior",
        );
    }
    if matches!(
        finding.static_proof_state,
        Some(StaticProofState::StaticallyRejected)
    ) || matches!(
        finding.triage.as_ref().map(|triage| triage.verdict),
        Some(TriageVerdict::FalsePositive | TriageVerdict::ByDesign)
    ) {
        return proof_ladder(
            "rejected",
            "rejected - evidence does not support exploitability",
            "triage or static proof rejected the issue",
            "suppress with expiry if the operator accepts the evidence",
        );
    }
    proof_ladder(
        "suspected",
        "suspected - needs source grounding or validation",
        "scanner signal has not been promoted with inspectable proof",
        "open the finding, collect code evidence, then validate if warranted",
    )
}

fn proof_ladder(stage: &str, label: &str, reason: &str, next_step: &str) -> ProofLadderState {
    ProofLadderState {
        stage: stage.to_string(),
        label: label.to_string(),
        reason: reason.to_string(),
        next_step: next_step.to_string(),
    }
}

fn indent_lines(value: &str) -> Vec<String> {
    value
        .lines()
        .map(|line| format!("  {}", line.trim_end()))
        .collect()
}
