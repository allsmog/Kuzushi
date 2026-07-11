use super::*;

pub(in crate::modules) struct SastPipelineReports {
    pub(in crate::modules) native: Option<ScanRun>,
    pub(in crate::modules) agentic: Option<AgenticSastReport>,
    pub(in crate::modules) carlini: Option<CarliniThreatHuntReport>,
    pub(in crate::modules) taint_iris_next: Option<TaintIrisNextReport>,
    pub(in crate::modules) systems_hunt: Option<SystemsHuntReport>,
    pub(in crate::modules) engine_ids: Vec<&'static str>,
    pub(in crate::modules) skipped_engines: Vec<crate::scan::SkippedDefaultScanEngine>,
}
