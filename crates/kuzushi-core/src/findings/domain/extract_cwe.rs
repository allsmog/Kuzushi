use super::*;

pub fn extract_cwe(rule_id: &str, title: &str, message: &str) -> Option<String> {
    [rule_id, title, message]
        .into_iter()
        .find_map(extract_cwe_from_source)
}

fn extract_cwe_from_source(source: &str) -> Option<String> {
    let upper = source.to_ascii_uppercase();
    for (index, _) in upper.match_indices("CWE") {
        let digits = cwe_digits(&upper[index + 3..]);
        if !digits.is_empty() {
            return Some(format!("CWE-{digits}"));
        }
    }
    None
}

fn cwe_digits(value: &str) -> String {
    value
        .trim_start_matches(['-', '_', ' ', ':'])
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect()
}

impl Finding {
    pub fn new_tool(
        tool: impl Into<String>,
        rule_id: impl Into<String>,
        file_path: impl Into<String>,
        start_line: u32,
        end_line: Option<u32>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        let tool = tool.into();
        let rule_id = rule_id.into();
        let file_path = file_path.into();
        let message = message.into();
        let fingerprint = fingerprint_parts(&rule_id, &file_path, start_line, &message);
        let title = finding_title(&message, &rule_id);
        let cwe = extract_cwe(&rule_id, &title, &message);
        let dedup_key = finding_dedup_key(&file_path, start_line, cwe.as_deref());
        let vuln_source = Some(VulnSource::from_tool(&tool));

        Self {
            id: None,
            scan_id: None,
            fingerprint,
            rule_id,
            title,
            severity,
            file_path,
            start_line,
            end_line,
            message,
            tool,
            actor_fingerprint: None,
            static_proof_state: None,
            triage: None,
            verification: None,
            created_at: now_isoish(),
            vuln_source,
            dedup_key,
            evidence: Vec::new(),
        }
    }

    /// Override the auto-detected vuln source (e.g. when reusing
    /// `new_tool` for a finding that should belong to a non-default
    /// channel).
    pub fn with_vuln_source(mut self, source: VulnSource) -> Self {
        self.vuln_source = Some(source);
        self
    }

    /// Override the auto-computed dedup key.
    pub fn with_dedup_key(mut self, key: impl Into<String>) -> Self {
        self.dedup_key = Some(key.into());
        self
    }

    pub fn with_evidence(mut self, evidence: Vec<FindingEvidence>) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn new_semgrep(
        rule_id: impl Into<String>,
        file_path: impl Into<String>,
        start_line: u32,
        end_line: Option<u32>,
        severity: Severity,
        message: impl Into<String>,
    ) -> Self {
        Self::new_tool(
            "semgrep", rule_id, file_path, start_line, end_line, severity, message,
        )
        .with_static_proof_state(StaticProofState::SignalOnly)
    }

    pub fn with_static_proof_state(mut self, state: StaticProofState) -> Self {
        self.static_proof_state = Some(state);
        self
    }

    pub fn set_static_proof_state(&mut self, state: StaticProofState) {
        self.static_proof_state = Some(state);
    }

    pub fn set_static_proof_state_from_str(&mut self, state: &str) -> Result<()> {
        self.static_proof_state = Some(StaticProofState::try_from(state)?);
        Ok(())
    }
}

fn finding_title(message: &str, rule_id: &str) -> String {
    message
        .lines()
        .next()
        .unwrap_or(rule_id)
        .trim()
        .to_string()
}

fn finding_dedup_key(file_path: &str, start_line: u32, cwe: Option<&str>) -> Option<String> {
    cwe.map(|cwe| compute_dedup_key(file_path, start_line, Some(cwe)))
}
