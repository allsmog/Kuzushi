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
    pub max_entries: usize,
    pub max_total_bytes: u64,
}

impl Default for IacScanOptions {
    fn default() -> Self {
        Self {
            kind: IacScanKind::All,
            max_file_bytes: 512 * 1024,
            max_entries: 100_000,
            max_total_bytes: 512 * 1024 * 1024,
        }
    }
}

impl IacScanOptions {
    pub(crate) fn check_limits(&self) -> Result<()> {
        anyhow::ensure!(
            (1024..=MAX_SUPPORTED_FILE_BYTES).contains(&self.max_file_bytes),
            "iac-scan: maxFileBytes outside supported range"
        );
        anyhow::ensure!(
            (1..=100_000).contains(&self.max_entries),
            "iac-scan: maxEntries outside supported range"
        );
        anyhow::ensure!(
            (1024..=536_870_912).contains(&self.max_total_bytes),
            "iac-scan: maxTotalBytes outside supported range"
        );
        Ok(())
    }
    pub fn from_tool_input(input: &Value) -> Result<Self> {
        let mut options = Self::default();
        if let Some(kind) = input.get("kind").and_then(Value::as_str) {
            options.kind = IacScanKind::from_input(kind)?;
        }
        options.max_file_bytes = read_limit(
            input,
            "maxFileBytes",
            options.max_file_bytes,
            1024,
            MAX_SUPPORTED_FILE_BYTES,
        )?;
        options.max_entries =
            read_limit(input, "maxEntries", options.max_entries as u64, 1, 100_000)? as usize;
        options.max_total_bytes = read_limit(
            input,
            "maxTotalBytes",
            options.max_total_bytes,
            1024,
            536_870_912,
        )?;
        Ok(options)
    }
}

fn read_limit(input: &Value, key: &str, default: u64, minimum: u64, maximum: u64) -> Result<u64> {
    let Some(raw) = input.get(key) else {
        return Ok(default);
    };
    let value = raw
        .as_u64()
        .with_context(|| format!("iac-scan: {key} must be an integer"))?;
    anyhow::ensure!(
        (minimum..=maximum).contains(&value),
        "iac-scan: {key} must be between {minimum} and {maximum}"
    );
    Ok(value)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IacInspection {
    pub entries_visited: usize,
    pub bytes_read: u64,
    pub symlinks_excluded: usize,
    pub directories_excluded: usize,
    pub max_entries: usize,
    pub max_total_bytes: u64,
    pub max_file_bytes: u64,
    pub max_depth: usize,
}

impl IacInspection {
    pub(super) fn is_unavailable(&self) -> bool {
        self.max_depth == 0
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
    #[serde(default, skip_serializing_if = "IacInspection::is_unavailable")]
    pub inspection: IacInspection,
}
