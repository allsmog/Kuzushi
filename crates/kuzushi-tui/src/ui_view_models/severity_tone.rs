use kuzushi_core::Severity;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum SeverityTone {
    Critical,
    High,
    Medium,
    Low,
    Info,
    #[default]
    Unknown,
}

impl SeverityTone {
    pub(crate) fn from_severity(severity: Severity) -> Self {
        match severity {
            Severity::Critical => Self::Critical,
            Severity::High => Self::High,
            Severity::Medium => Self::Medium,
            Severity::Low => Self::Low,
            Severity::Info => Self::Info,
            Severity::Unknown => Self::Unknown,
        }
    }
}
