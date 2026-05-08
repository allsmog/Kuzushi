use super::*;

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
