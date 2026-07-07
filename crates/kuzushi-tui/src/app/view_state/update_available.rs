#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateAvailableSnapshot {
    pub status: UpdateAvailableStatus,
    pub body_rows: Vec<String>,
    pub footer: UpdateAvailableFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateAvailableStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpdateAvailableFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
