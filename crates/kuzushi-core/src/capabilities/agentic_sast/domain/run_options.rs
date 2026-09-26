/// Turn budget for one agentic hunt when the operator sets none: the hunt
/// starts from an ~80-snippet inventory and reads further files, and 20 turns
/// stays inside a 200k-token window with bounded tool results.
pub(crate) const DEFAULT_AGENTIC_MODEL_TURNS: u32 = 20;

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
    pub(crate) max_model_turns: Option<u32>,
}
