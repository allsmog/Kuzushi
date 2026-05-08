use super::*;

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

pub(in crate::modules) struct SastScanRequests {
    pub(in crate::modules) verify: bool,
    pub(in crate::modules) auto_patch: bool,
    pub(in crate::modules) triage: bool,
}

impl SastScanRequests {
    pub(in crate::modules) fn from_input(input: &Value) -> Result<Self> {
        let verify = bool_input(input, &["verify"])?;
        let auto_patch = bool_input(input, &["autoPatch", "auto_patch"])?;
        let triage =
            bool_input(input, &["triage", "aiTriage", "ai_triage"])? || verify || auto_patch;
        Ok(Self {
            verify,
            auto_patch,
            triage,
        })
    }

    pub(in crate::modules) fn needs_verification(&self) -> bool {
        self.verify || self.auto_patch
    }
}

pub(in crate::modules) fn sast_scan_options(
    input: &Value,
    whitebox_static: bool,
) -> Result<ScanRunOptions> {
    Ok(ScanRunOptions {
        severity: parse_sast_severity_filter(input)?,
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
