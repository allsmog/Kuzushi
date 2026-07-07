#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionsScreenSnapshot {
    pub status: OptionsScreenStatus,
    pub body_rows: Vec<String>,
    pub footer: OptionsScreenFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionsScreenStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionsScreenFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
