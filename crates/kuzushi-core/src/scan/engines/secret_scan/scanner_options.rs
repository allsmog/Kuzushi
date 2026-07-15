use super::*;

pub(crate) const MAX_SUPPORTED_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MIN_FILE_BYTES: u64 = 1024;
const MAX_SUPPORTED_FINDINGS: u64 = 10_000;

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
        options.apply_limits(input)?;
        options.extend_excluded_directories(input);
        options.extend_binary_extensions(input);
        options.apply_severity_filter(input)?;
        Ok(options)
    }

    fn apply_limits(&mut self, input: &Value) -> Result<()> {
        if let Some(value) = bounded_u64(input, "maxFileBytes", MIN_FILE_BYTES, MAX_SUPPORTED_FILE_BYTES)? {
            self.max_file_bytes = value;
        }
        if let Some(value) = bounded_u64(input, "maxFindings", 1, MAX_SUPPORTED_FINDINGS)? {
            self.max_findings = value as usize;
        }
        Ok(())
    }

    fn extend_excluded_directories(&mut self, input: &Value) {
        if let Some(values) = input.get("excludeDirs").and_then(Value::as_array) {
            for value in values.iter().filter_map(Value::as_str) {
                if !value.trim().is_empty() {
                    self.exclude_dirs.insert(value.trim().to_string());
                }
            }
        }
    }

    fn extend_binary_extensions(&mut self, input: &Value) {
        if let Some(values) = input.get("binaryExts").and_then(Value::as_array) {
            for value in values.iter().filter_map(Value::as_str) {
                if let Some(extension) = normalize_binary_extension(value) {
                    self.binary_exts.insert(extension);
                }
            }
        }
    }

    fn apply_severity_filter(&mut self, input: &Value) -> Result<()> {
        if let Some(values) = input.get("severity").and_then(Value::as_array) {
            let mut severities = BTreeSet::new();
            for value in values.iter().filter_map(Value::as_str) {
                severities.insert(SecretSeverity::try_from(value)?);
            }
            self.severity = Some(severities);
        }
        Ok(())
    }
}

fn bounded_u64(input: &Value, name: &str, minimum: u64, maximum: u64) -> Result<Option<u64>> {
    let Some(raw) = input.get(name) else {
        return Ok(None);
    };
    let value = raw
        .as_u64()
        .with_context(|| format!("{name} must be an integer from {minimum} to {maximum}"))?;
    anyhow::ensure!(
        (minimum..=maximum).contains(&value),
        "{name} must be from {minimum} to {maximum}, got {value}"
    );
    Ok(Some(value))
}

fn normalize_binary_extension(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let normalized = trimmed.to_ascii_lowercase();
    Some(if normalized.starts_with('.') {
        normalized
    } else {
        format!(".{normalized}")
    })
}

#[derive(Debug, Clone, Default)]
pub struct SecretScanScanner;
