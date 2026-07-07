#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSplashSnapshot {
    pub version_line: String,
    pub checks: Vec<BootSplashCheck>,
    pub primary_hint: String,
    pub secondary_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootSplashCheck {
    pub state: BootSplashCheckState,
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BootSplashCheckState {
    Ok,
    Wait,
    Err,
}

impl BootSplashCheck {
    pub fn new(
        state: BootSplashCheckState,
        label: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            state,
            label: label.into(),
            value: value.into(),
        }
    }
}
