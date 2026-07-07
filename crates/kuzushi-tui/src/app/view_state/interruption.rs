use super::InterruptionView;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptionSnapshot {
    pub view: InterruptionView,
    pub status: InterruptionStatus,
    pub body_rows: Vec<String>,
    pub footer: InterruptionFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptionStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterruptionFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
