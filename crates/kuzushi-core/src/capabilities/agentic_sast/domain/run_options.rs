#[derive(Debug, Clone)]
pub(crate) struct AgenticSastInput {
    pub(crate) max_findings: usize,
    pub(crate) passes: usize,
    pub(crate) max_inventory_files: usize,
    pub(crate) max_bytes_per_file: usize,
    pub(crate) severity: Vec<String>,
    pub(crate) focus: Option<String>,
    pub(crate) include_patterns: Vec<String>,
    pub(crate) exclude_patterns: Vec<String>,
}
