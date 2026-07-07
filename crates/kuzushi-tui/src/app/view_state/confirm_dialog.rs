#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmDialogSnapshot {
    pub status: ConfirmDialogStatus,
    pub body_rows: Vec<String>,
    pub footer: ConfirmDialogFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmDialogStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmDialogFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
