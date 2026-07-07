#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeymapSnapshot {
    pub status: KeymapStatus,
    pub event_time: String,
    pub sections: Vec<KeymapSection>,
    pub note: String,
    pub footer: KeymapFooter,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeymapStatus {
    pub target: String,
    pub ctx: String,
    pub model: String,
    pub module: String,
    pub cost: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeymapSection {
    pub name: String,
    pub blurb: String,
    pub rows: Vec<KeymapBindingRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeymapBindingRow {
    pub keys: String,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeymapFooter {
    pub stage: String,
    pub findings: usize,
    pub keybinds: Vec<(String, String)>,
    pub prompt_module: String,
}

impl KeymapSection {
    pub fn new(
        name: impl Into<String>,
        blurb: impl Into<String>,
        rows: Vec<KeymapBindingRow>,
    ) -> Self {
        Self {
            name: name.into(),
            blurb: blurb.into(),
            rows,
        }
    }
}

impl KeymapBindingRow {
    pub fn new(keys: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            keys: keys.into(),
            action: action.into(),
        }
    }
}
