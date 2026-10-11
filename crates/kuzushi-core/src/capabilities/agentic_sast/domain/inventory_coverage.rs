use serde::{Deserialize, Serialize};

/// Preparation extent only; agent tool reads and repository coverage are separate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgenticInventoryCoverage {
    pub enumerated_entries: usize,
    pub selected_files: usize,
    pub ignored_entries: usize,
    pub skipped_entries: usize,
    pub max_entries: usize,
    pub max_files: usize,
    pub max_file_read_bytes: usize,
    pub max_snippet_bytes: usize,
    pub snippet_bytes: usize,
    pub entry_limit_reached: bool,
    pub read_limit_reached: bool,
    pub max_read_bytes: usize,
    /// Conservative reservation, including failed and binary-looking reads.
    pub reserved_read_bytes: usize,
    pub truncation: Option<String>,
}

impl AgenticInventoryCoverage {
    pub(crate) fn reading_lines(&self) -> Vec<String> {
        let mut lines = vec![
            format!("Source preparation: {} snippets · {} entries · {} skipped entries · {} ignored entries", self.selected_files, self.enumerated_entries, self.skipped_entries, self.ignored_entries),
            format!("Preparation limits: {} entries · {} files · {} snippet bytes before decoding · {} bytes maximum file read including binary inspection · {} bytes total read allowance. Snippets do not establish repository coverage.", self.max_entries, self.max_files, self.max_snippet_bytes, self.max_file_read_bytes, self.max_read_bytes),
        ];
        if let Some(reason) = &self.truncation {
            lines.push(format!("Partial preparation: {reason}"));
        }
        lines
    }
}
