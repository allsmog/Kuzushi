use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceTarget {
    pub(crate) root: PathBuf,
}

impl WorkspaceTarget {
    pub fn new(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let root = if path.exists() {
            fs::canonicalize(path)
                .with_context(|| format!("Could not resolve {}", path.display()))?
        } else {
            anyhow::bail!("Target path does not exist: {}", path.display());
        };

        if !root.is_dir() {
            anyhow::bail!("Target must be a directory: {}", root.display());
        }

        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join(".kuzushi").join("v2")
    }

    pub fn findings_db_path(&self) -> PathBuf {
        self.state_dir().join("findings.sqlite3")
    }

    pub fn ensure_state_dir(&self) -> Result<PathBuf> {
        let state_dir = self.state_dir();
        fs::create_dir_all(&state_dir)
            .with_context(|| format!("Could not create {}", state_dir.display()))?;
        Ok(state_dir)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceExportFormat {
    Json,
    Jsonl,
}

impl WorkspaceExportFormat {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "jsonl" | "ndjson" => Ok(Self::Jsonl),
            other => anyhow::bail!(
                "unsupported workspace findings export format {other:?}. Supported formats: json, jsonl"
            ),
        }
    }

    pub fn from_output_path(path: &Path) -> Result<Self> {
        match path.extension().and_then(|extension| extension.to_str()) {
            Some("json") | None => Ok(Self::Json),
            Some("jsonl") | Some("ndjson") => Ok(Self::Jsonl),
            Some(other) => anyhow::bail!(
                "unsupported workspace findings export extension .{other}. Supported extensions: .json, .jsonl"
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFindingsExport {
    pub output_path: PathBuf,
    pub format: WorkspaceExportFormat,
    pub count: usize,
}
