#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigScreenSnapshot {
    pub status: ConfigScreenStatus,
    pub body_rows: Vec<String>,
    pub footer: ConfigScreenFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigScreenStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigScreenFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
