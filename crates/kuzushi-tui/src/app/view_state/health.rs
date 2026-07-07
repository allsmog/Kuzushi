#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthSnapshot {
    pub status: HealthStatus,
    pub body_rows: Vec<String>,
    pub footer: HealthFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
