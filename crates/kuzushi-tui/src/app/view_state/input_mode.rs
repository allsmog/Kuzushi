#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Prompt,
    Navigate,
}

impl InputMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Prompt => "prompt",
            Self::Navigate => "nav",
        }
    }
}
