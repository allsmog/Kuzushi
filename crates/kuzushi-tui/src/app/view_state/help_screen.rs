#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpScreenSnapshot {
    pub status: HelpScreenStatus,
    pub body_rows: Vec<String>,
    pub footer: HelpScreenFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpScreenStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelpScreenFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
