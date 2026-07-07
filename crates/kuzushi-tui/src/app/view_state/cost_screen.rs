#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostScreenSnapshot {
    pub status: CostScreenStatus,
    pub body_rows: Vec<String>,
    pub footer: CostScreenFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostScreenStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostScreenFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
