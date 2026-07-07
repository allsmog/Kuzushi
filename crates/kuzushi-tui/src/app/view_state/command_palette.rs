#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPaletteSnapshot {
    pub status: CommandPaletteStatus,
    pub body_rows: Vec<String>,
    pub footer: CommandPaletteFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPaletteStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandPaletteFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: Option<String>,
}
