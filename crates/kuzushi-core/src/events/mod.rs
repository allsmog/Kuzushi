/// Live progress state for an in-flight scan, emitted/updated by scan
/// orchestrators and consumed by the TUI to drive real `done/total`
/// progress bars instead of binary "running/done" placeholders.
#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub total: usize,
    pub done: usize,
    pub current_tool: Option<String>,
    pub current_target: Option<String>,
    /// Per-task progress: `{ "semgrep" => (done, total), ... }`.
    pub per_task: std::collections::BTreeMap<String, (usize, usize)>,
}

impl ScanProgress {
    pub fn percent(&self) -> u8 {
        if self.total == 0 {
            0
        } else {
            ((self.done as f64 / self.total as f64) * 100.0).round() as u8
        }
    }
}
