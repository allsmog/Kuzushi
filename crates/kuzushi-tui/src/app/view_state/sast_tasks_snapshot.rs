#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SastTasksSnapshot {
    pub status: SastTasksStatus,
    pub body_rows: Vec<String>,
    pub footer: SastTasksFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SastTasksStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SastTasksFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
