#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemePickerSnapshot {
    pub status: ThemePickerStatus,
    pub event_time: String,
    pub current_theme: String,
    pub source_hint: String,
    pub tty_override_hint: String,
    pub palettes: Vec<ThemePaletteRow>,
    pub selected_palette: usize,
    pub preview_title: String,
    pub preview_rows: Vec<String>,
    pub accessibility_rows: Vec<String>,
    pub custom_rows: Vec<String>,
    pub flow_time: String,
    pub flow_hint: String,
    pub footer: ThemePickerFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemePickerStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemePaletteRow {
    pub name: String,
    pub background: String,
    pub foreground: String,
    pub accent: String,
    pub severity: String,
    pub blurb: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThemePickerFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: String,
}

impl ThemePaletteRow {
    pub fn new(
        name: impl Into<String>,
        background: impl Into<String>,
        foreground: impl Into<String>,
        accent: impl Into<String>,
        severity: impl Into<String>,
        blurb: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            background: background.into(),
            foreground: foreground.into(),
            accent: accent.into(),
            severity: severity.into(),
            blurb: blurb.into(),
        }
    }
}
