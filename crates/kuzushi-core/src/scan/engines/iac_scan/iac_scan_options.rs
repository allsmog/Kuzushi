use super::*;

pub(super) const MAX_SUPPORTED_FILE_BYTES: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum IacScanKind {
    Dockerfile,
    GithubActions,
    Terraform,
    All,
}

impl Default for IacScanKind {
    fn default() -> Self {
        Self::All
    }
}

impl IacScanKind {
    pub(crate) fn from_input(value: &str) -> Result<Self> {
        match value.trim() {
            "dockerfile" | "docker" => Ok(Self::Dockerfile),
            "github-actions" | "github_actions" | "actions" => Ok(Self::GithubActions),
            "terraform" | "tf" => Ok(Self::Terraform),
            "all" | "" => Ok(Self::All),
            other => anyhow::bail!(
                "iac-scan: unknown kind {other:?}; expected dockerfile, github-actions, terraform, or all"
            ),
        }
    }

    pub(crate) fn includes(self, other: Self) -> bool {
        self == Self::All || self == other
    }
}

#[derive(Debug, Clone)]
pub struct IacScanOptions {
    pub kind: IacScanKind,
    pub max_file_bytes: u64,
}

impl Default for IacScanOptions {
    fn default() -> Self {
        Self {
            kind: IacScanKind::All,
            max_file_bytes: 512 * 1024,
        }
    }
}

impl IacScanOptions {
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut options = Self::default();
        if let Some(kind) = input.get("kind").and_then(Value::as_str) {
            options.kind = IacScanKind::from_input(kind)?;
        }
        if let Some(max_file_bytes) = input.get("maxFileBytes").and_then(Value::as_u64) {
            options.max_file_bytes = max_file_bytes.clamp(1024, MAX_SUPPORTED_FILE_BYTES);
        }
        Ok(options)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IacScanReport {
    pub target: String,
    pub kind: IacScanKind,
    pub findings: Vec<IacScanFinding>,
    pub files_scanned: usize,
    pub files_skipped: usize,
    /// Paths the walk reached but could not read. A clean report over a tree
    /// with gaps has not cleared the whole tree.
    #[serde(default)]
    pub coverage_gaps: CoverageGaps,
}
