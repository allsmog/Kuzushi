use super::prelude::*;
use super::*;

pub fn extract_cwe(rule_id: &str, title: &str, message: &str) -> Option<String> {
    for source in [rule_id, title, message] {
        let lower = source.to_ascii_lowercase();
        let mut idx = 0;
        while let Some(pos) = lower[idx..].find("cwe-") {
            let start = idx + pos + 4;
            let digits: String = lower[start..]
                .chars()
                .take_while(|c| c.is_ascii_digit())
                .collect();
            if !digits.is_empty() {
                return Some(format!("CWE-{digits}"));
            }
            idx = start;
        }
    }
    None
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
        let title = message
            .lines()
            .next()
            .unwrap_or(&rule_id)
            .trim()
            .to_string();

        let cwe = extract_cwe(&rule_id, &title, &message);
        // Only auto-populate dedup_key when we extracted a real CWE.
        // Without CWE the bucket would collide too aggressively across
        // unrelated findings — fingerprint dedup is the right level
        // there, and callers that want stronger collisions can attach a
        // dedup_key explicitly with `with_dedup_key`.
        let dedup_key = cwe
            .as_deref()
            .map(|c| compute_dedup_key(&file_path, start_line, Some(c)));
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
