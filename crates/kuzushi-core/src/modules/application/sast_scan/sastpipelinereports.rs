use super::*;

pub(in crate::modules) struct SastPipelineReports {
    pub(in crate::modules) native: Option<ScanRun>,
    pub(in crate::modules) agentic: Option<AgenticSastReport>,
    pub(in crate::modules) carlini: Option<CarliniThreatHuntReport>,
    pub(in crate::modules) taint_iris_next: Option<TaintIrisNextReport>,
    pub(in crate::modules) systems_hunt: Option<SystemsHuntReport>,
    pub(in crate::modules) engine_ids: Vec<&'static str>,
    pub(in crate::modules) engine_outcomes:
        std::collections::BTreeMap<&'static str, crate::run_artifacts::ScanEngineStageOutcome>,
    pub(in crate::modules) skipped_engines: Vec<crate::scan::SkippedDefaultScanEngine>,
    /// Why a dispatched engine reported `skipped` (for example it does not
    /// apply to the target), keyed like `engine_outcomes`.
    pub(in crate::modules) engine_skip_reasons: std::collections::BTreeMap<&'static str, String>,
}
