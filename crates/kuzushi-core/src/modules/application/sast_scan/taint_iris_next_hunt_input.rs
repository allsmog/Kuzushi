use super::*;
use crate::{Finding, Severity};

pub(in crate::modules) fn taint_iris_next_hunt_input(input: &Value) -> Value {
    let mut next_input = input.clone();
    if let Value::Object(object) = &mut next_input {
        if should_force_taint_iris_next_hunt_mode(object.get("mode")) {
            object.insert("mode".to_string(), json!("hunt"));
        }
    }
    next_input
}

pub(in crate::modules) fn should_force_taint_iris_next_hunt_mode(mode: Option<&Value>) -> bool {
    mode.and_then(Value::as_str)
        .map(str::trim)
        .map(|mode| matches!(mode, "standard" | "whitebox-static"))
        .unwrap_or(true)
}

#[derive(Debug)]
pub(in crate::modules) struct SastScanRequests {
    pub(in crate::modules) verify: bool,
    pub(in crate::modules) auto_patch: bool,
    pub(in crate::modules) triage: bool,
    pub(in crate::modules) verify_when: SastVerifyWhen,
    pub(in crate::modules) verify_max: Option<usize>,
    pub(in crate::modules) verify_votes: Option<usize>,
    /// Refine the active threat model with confirmed findings after triage.
    pub(in crate::modules) threat_model_feedback: bool,
}

impl SastScanRequests {
    pub(in crate::modules) fn from_input(input: &Value) -> Result<Self> {
        let verify = bool_input(input, &["verify"])?;
        let auto_patch = bool_input(input, &["autoPatch", "auto_patch"])?;
        let triage =
            bool_input(input, &["triage", "aiTriage", "ai_triage"])? || verify || auto_patch;
        let verify_when = SastVerifyWhen::from_input(input)?;
        let verify_max = optional_usize_input(input, &["verifyMax", "verify_max"])?;
        let verify_votes = optional_usize_input(input, &["verifyVotes", "verify_votes"])?;
        let threat_model_feedback = input
            .get("threatModelFeedback")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode == "refine");
        Ok(Self {
            verify,
            auto_patch,
            triage,
            verify_when,
            verify_max,
            verify_votes,
            threat_model_feedback,
        })
    }

    pub(in crate::modules) fn needs_verification(&self) -> bool {
        self.verify || self.auto_patch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::modules) struct SastVerifyWhen {
    min_severity: Option<Severity>,
}

impl SastVerifyWhen {
    fn from_input(input: &Value) -> Result<Self> {
        let Some(raw) = optional_string_input(input, &["verifyWhen", "verify_when"])? else {
            return Ok(Self::all());
        };
        Self::parse(&raw)
    }

    fn all() -> Self {
        Self { min_severity: None }
    }

    fn parse(raw: &str) -> Result<Self> {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() || normalized == "all" {
            return Ok(Self::all());
        }
        let Some(severity) = normalized.strip_prefix("severity>=") else {
            anyhow::bail!("sast:scan verifyWhen must be \"all\" or \"severity>=<level>\"");
        };
        Ok(Self {
            min_severity: Some(parse_sast_severity(severity)?),
        })
    }

    pub(in crate::modules) fn matches(self, finding: &Finding) -> bool {
        self.min_severity
            .map(|min| severity_rank(finding.severity) >= severity_rank(min))
            .unwrap_or(true)
    }
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 5,
        Severity::High => 4,
        Severity::Medium => 3,
        Severity::Low => 2,
        Severity::Info => 1,
        Severity::Unknown => 0,
    }
}

pub(in crate::modules) fn sast_scan_options(
    input: &Value,
    whitebox_static: bool,
) -> Result<ScanRunOptions> {
    Ok(ScanRunOptions {
        run_id: string_input_any(input, &["runId", "run_id"]),
        severity: parse_sast_severity_filter(input)?,
        paths: string_list_input(input, &["paths", "includePaths", "include_paths"])?
            .unwrap_or_default(),
        tasks: None,
        static_proof_state: whitebox_static.then_some(StaticProofState::SignalOnly),
        index_static_evidence: whitebox_static,
    })
}

#[derive(Default)]
pub(in crate::modules) struct WhiteboxArtifacts {
    pub(in crate::modules) static_ranking: Option<Value>,
    pub(in crate::modules) static_narratives: Option<Value>,
    pub(in crate::modules) static_variants: Option<Value>,
    pub(in crate::modules) candidate_semgrep_rules: Option<Value>,
    pub(in crate::modules) whitebox_suppressions: Option<Value>,
    pub(in crate::modules) whitebox_diff: Option<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_refine_requests_threat_model_feedback() {
        let refine =
            SastScanRequests::from_input(&json!({"threatModelFeedback": "refine"})).unwrap();
        let off = SastScanRequests::from_input(&json!({"threatModelFeedback": "off"})).unwrap();

        assert!(refine.threat_model_feedback);
        assert!(!off.threat_model_feedback);
        assert!(
            !SastScanRequests::from_input(&json!({}))
                .unwrap()
                .threat_model_feedback
        );
    }

    #[test]
    fn verify_controls_parse_aliases() {
        let requests = SastScanRequests::from_input(&json!({
            "verify": true,
            "verify_when": "severity>=high",
            "verify_max": 3,
            "verify_votes": 2
        }))
        .unwrap();

        assert!(requests.needs_verification());
        assert_eq!(requests.verify_max, Some(3));
        assert_eq!(requests.verify_votes, Some(2));
        assert!(requests.verify_when.matches(&Finding::new_tool(
            "semgrep",
            "rule/cwe-89",
            "src/app.rs",
            1,
            None,
            Severity::High,
            "SQL injection CWE-89",
        )));
        assert!(!requests.verify_when.matches(&Finding::new_tool(
            "semgrep",
            "rule/cwe-89",
            "src/app.rs",
            1,
            None,
            Severity::Medium,
            "SQL injection CWE-89",
        )));
    }

    #[test]
    fn verify_controls_reject_unknown_when_shape() {
        let error = SastScanRequests::from_input(&json!({
            "verifyWhen": "confidence>=0.8"
        }))
        .unwrap_err()
        .to_string();

        assert!(error.contains("verifyWhen"));
    }
}
