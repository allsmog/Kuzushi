#[derive(Debug, Clone)]
pub(crate) struct AgenticSastInput {
    pub(crate) max_findings: usize,
    pub(crate) passes: usize,
    pub(crate) severity: Vec<String>,
    pub(crate) exclude_patterns: Vec<String>,
}
