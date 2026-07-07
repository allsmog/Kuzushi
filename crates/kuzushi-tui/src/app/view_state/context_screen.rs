#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextScreenSnapshot {
    pub status: ContextScreenStatus,
    pub body_rows: Vec<String>,
    pub footer: ContextScreenFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextScreenStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextScreenFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
