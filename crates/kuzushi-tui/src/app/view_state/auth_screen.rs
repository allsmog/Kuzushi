#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthScreenSnapshot {
    pub status: AuthScreenStatus,
    pub body_rows: Vec<String>,
    pub footer: AuthScreenFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthScreenStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthScreenFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
