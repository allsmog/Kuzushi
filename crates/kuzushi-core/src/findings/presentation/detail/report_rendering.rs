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
        let mut lines = Vec::new();
        self.append_header_lines(&mut lines);
        self.append_message_lines(&mut lines);
        self.append_proof_lines(&mut lines);
        self.append_triage_lines(&mut lines);
        self.append_verification_lines(&mut lines);
        self.append_patch_lines(&mut lines);
        lines.push(String::new());
        lines.push(format!("Next action: {}", self.next_action.as_str()));
        lines.join("\n")
    }

    fn append_header_lines(&self, lines: &mut Vec<String>) {
        let finding = &self.finding;
        lines.push(self.title_line());
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
    }

    fn title_line(&self) -> String {
        match &self.alias {
            Some(alias) => format!("Finding {alias}"),
            None => "Finding".to_string(),
        }
    }

    fn append_message_lines(&self, lines: &mut Vec<String>) {
        lines.push(String::new());
        lines.push("Message:".to_string());
        lines.extend(indent_lines(&self.finding.message));
    }

    fn append_proof_lines(&self, lines: &mut Vec<String>) {
        lines.push(String::new());
        lines.push(format!("Proof state: {}", self.proof_state));
        lines.push(format!("Runtime validation: {}", self.runtime_validation));
        lines.push(format!(
            "Proof ladder: {} - {}",
            self.proof_ladder.stage, self.proof_ladder.reason
        ));
        lines.push(format!("Next proof step: {}", self.proof_ladder.next_step));
    }

    fn append_triage_lines(&self, lines: &mut Vec<String>) {
        let Some(triage) = &self.finding.triage else {
            return;
        };
        lines.push(String::new());
        lines.push("Triage:".to_string());
        lines.push(format!("  Verdict: {}", triage.verdict.as_str()));
        lines.push(format!("  Confidence: {:.2}", triage.confidence));
        lines.push(format!("  Rationale: {}", triage.rationale));
        lines.push(format!("  Cost USD: {:.4}", triage.cost_usd));
    }

    fn append_verification_lines(&self, lines: &mut Vec<String>) {
        let Some(verification) = &self.finding.verification else {
            return;
        };
        lines.push(String::new());
        lines.push("Verification:".to_string());
        lines.push(format!(
            "  Verdict: {}",
            verification.proof_verdict.as_str()
        ));
        lines.push(format!("  Proof level: {}", verification.proof_level));
        lines.push(format!("  Backend: {}", verification.backend.as_str()));
        append_optional_line(lines, "Language", verification.language.as_deref());
        append_optional_line(lines, "Harness", verification.harness_path.as_deref());
        append_optional_line(lines, "Evidence", verification.crash_evidence.as_deref());
        append_notes_line(lines, &verification.notes);
    }

    fn append_patch_lines(&self, lines: &mut Vec<String>) {
        lines.push(String::new());
        lines.push("Patch result:".to_string());
        if let Some(patch) = self.patch_results.first() {
            lines.push(format!("  Status: {}", patch.status.as_str()));
            lines.push(format!("  Iterations: {}", patch.iterations));
            append_optional_line(lines, "Test command", patch.test_command.as_deref());
            append_optional_line(lines, "Worktree", patch.worktree_path.as_deref());
        } else {
            lines.push("  not recorded".to_string());
        }
    }
}

fn append_optional_line(lines: &mut Vec<String>, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        lines.push(format!("  {label}: {value}"));
    }
}

fn append_notes_line(lines: &mut Vec<String>, notes: &[String]) {
    if !notes.is_empty() {
        lines.push(format!("  Notes: {}", notes.join("; ")));
    }
}
