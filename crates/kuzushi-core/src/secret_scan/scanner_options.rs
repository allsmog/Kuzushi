use super::*;

impl SecretSeverity {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Error => "ERROR",
            Self::Warning => "WARNING",
            Self::Info => "INFO",
        }
    }

    pub(crate) fn to_core_severity(self) -> Severity {
        match self {
            Self::Error => Severity::High,
            Self::Warning => Severity::Medium,
            Self::Info => Severity::Info,
        }
    }
}

impl TryFrom<&str> for SecretSeverity {
    type Error = anyhow::Error;

    fn try_from(value: &str) -> Result<Self> {
        match value {
            "ERROR" => Ok(Self::Error),
            "WARNING" => Ok(Self::Warning),
            "INFO" => Ok(Self::Info),
            other => anyhow::bail!("unknown secret-scan severity {other:?}"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SecretScanOptions {
    pub max_file_bytes: u64,
    pub exclude_dirs: BTreeSet<String>,
    pub binary_exts: BTreeSet<String>,
    pub max_findings: usize,
    pub severity: Option<BTreeSet<SecretSeverity>>,
}

impl Default for SecretScanOptions {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_MAX_FILE_BYTES,
            exclude_dirs: DEFAULT_EXCLUDE_DIRS
                .iter()
                .map(|entry| (*entry).to_string())
                .collect(),
            binary_exts: DEFAULT_BINARY_EXTS
                .iter()
                .map(|entry| (*entry).to_string())
                .collect(),
            max_findings: DEFAULT_MAX_FINDINGS,
            severity: None,
        }
    }
}

impl SecretScanOptions {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut options = Self::default();

        if let Some(value) = input.get("maxFileBytes").and_then(Value::as_u64) {
            options.max_file_bytes = value.max(1024);
        }

        if let Some(value) = input.get("maxFindings").and_then(Value::as_u64) {
            options.max_findings = value.max(1).min(10_000) as usize;
        }

        if let Some(values) = input.get("excludeDirs").and_then(Value::as_array) {
            for value in values.iter().filter_map(Value::as_str) {
                if !value.trim().is_empty() {
                    options.exclude_dirs.insert(value.trim().to_string());
                }
            }
        }

        if let Some(values) = input.get("binaryExts").and_then(Value::as_array) {
            for value in values.iter().filter_map(Value::as_str) {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let ext = if trimmed.starts_with('.') {
                    trimmed.to_ascii_lowercase()
                } else {
                    format!(".{}", trimmed.to_ascii_lowercase())
                };
                options.binary_exts.insert(ext);
            }
        }

        if let Some(values) = input.get("severity").and_then(Value::as_array) {
            let mut severities = BTreeSet::new();
            for value in values.iter().filter_map(Value::as_str) {
                severities.insert(SecretSeverity::try_from(value)?);
            }
            options.severity = Some(severities);
        }

        Ok(options)
    }
}

#[derive(Debug, Clone, Default)]
pub struct SecretScanScanner;
