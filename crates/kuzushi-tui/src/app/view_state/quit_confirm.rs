#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuitConfirmSnapshot {
    pub status: QuitConfirmStatus,
    pub timestamp: String,
    pub warning_title: String,
    pub warning_body: String,
    pub sections: Vec<QuitConfirmSection>,
    pub default_line: String,
    pub footer: QuitConfirmFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuitConfirmStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuitConfirmSection {
    pub title: String,
    pub rows: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuitConfirmFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: String,
}

impl QuitConfirmSection {
    pub fn new(title: impl Into<String>, rows: Vec<String>) -> Self {
        Self {
            title: title.into(),
            rows,
        }
    }
}
