use super::*;

pub const KUZUSHI_STATE_DIR: &str = ".kuzushi";
pub const WORKSPACE_STATE_VERSION_DIR: &str = "v3";
pub const WORKSPACE_CONFIG_FILE: &str = "config.toml";
pub const WORKSPACE_OPTIONS_FILE: &str = "options.json";
pub const WORKSPACE_HISTORY_FILE: &str = "shell-history.txt";
pub const WORKSPACE_FINDINGS_DB_FILE: &str = "index.sqlite3";
pub const WORKSPACE_EVENT_LOG_DIR: &str = "log";
pub const WORKSPACE_OBJECTS_DIR: &str = "objects";
pub const WORKSPACE_STATIC_EVIDENCE_DB_FILE: &str = "static-evidence.sqlite3";
pub const WORKSPACE_ARTIFACT_KB_DB_FILE: &str = "artifact-kb.sqlite3";
pub const WORKSPACE_ATTACHMENTS_FILE: &str = "attachments.json";
pub const WORKSPACE_MODELS_FILE: &str = "models.toml";
pub const WORKSPACE_SUPPRESSIONS_FILE: &str = "suppressions.toml";
pub const WORKSPACE_CODEQL_DB_DIR: &str = "codeql-db";
pub const LEGACY_CODEQL_STATE_DIR: &str = ".codeql";
pub const LEGACY_CODEQL_DB_DIR: &str = "db";

pub fn workspace_state_root(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref().join(KUZUSHI_STATE_DIR)
}

pub fn workspace_state_dir(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_root(root).join(WORKSPACE_STATE_VERSION_DIR)
}

pub fn workspace_config_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_CONFIG_FILE)
}

pub fn workspace_options_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_OPTIONS_FILE)
}

pub fn workspace_history_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_HISTORY_FILE)
}

pub fn workspace_findings_db_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_FINDINGS_DB_FILE)
}

pub fn workspace_event_log_dir(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_EVENT_LOG_DIR)
}

pub fn workspace_objects_dir(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_OBJECTS_DIR)
}

pub fn workspace_static_evidence_db_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_STATIC_EVIDENCE_DB_FILE)
}

pub fn workspace_artifact_kb_db_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_ARTIFACT_KB_DB_FILE)
}

pub fn workspace_attachments_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_ATTACHMENTS_FILE)
}

pub fn workspace_models_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_root(root).join(WORKSPACE_MODELS_FILE)
}

/// Suppression rule store. Lives under `state_dir()` (`.kuzushi/v3/`) with
/// the other v3 stores, unlike `scope.toml`/`models.toml` which sit directly
/// under `.kuzushi/`.
pub fn workspace_suppressions_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_SUPPRESSIONS_FILE)
}

pub fn workspace_codeql_db_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(WORKSPACE_CODEQL_DB_DIR)
}

/// Pre-v3 managed CodeQL database path retained only for migration checks.
pub fn legacy_workspace_codeql_db_path(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_root(root).join(WORKSPACE_CODEQL_DB_DIR)
}

/// Legacy CodeQL CLI database path retained only for migration checks.
pub fn legacy_codeql_db_path(root: impl AsRef<Path>) -> PathBuf {
    root.as_ref()
        .join(LEGACY_CODEQL_STATE_DIR)
        .join(LEGACY_CODEQL_DB_DIR)
}

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
            anyhow::bail!(
                "Target path does not exist: {}. Next: use an existing directory; in the CLI, put the global target before the command, for example `kuzushi --target . scan`.",
                path.display()
            );
        };

        if !root.is_dir() {
            anyhow::bail!("Target must be a directory: {}", root.display());
        }

        validated_workspace_descendant(
            &root,
            Path::new(KUZUSHI_STATE_DIR).join(WORKSPACE_STATE_VERSION_DIR),
        )?;

        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn state_dir(&self) -> PathBuf {
        workspace_state_dir(&self.root)
    }

    pub fn findings_db_path(&self) -> PathBuf {
        workspace_findings_db_path(&self.root)
    }

    pub fn event_log_dir(&self) -> PathBuf {
        workspace_event_log_dir(&self.root)
    }

    pub fn objects_dir(&self) -> PathBuf {
        workspace_objects_dir(&self.root)
    }

    pub fn suppressions_path(&self) -> PathBuf {
        workspace_suppressions_path(&self.root)
    }

    pub fn ensure_state_dir(&self) -> Result<PathBuf> {
        initialize_workspace_state(&self.root)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceExportFormat {
    Json,
    Jsonl,
    Sarif,
    Csv,
    MarkdownBundle,
    /// External orchestration schema: `{"scan_completed":…,"findings":[…]}`
    /// with title/impact/file/line/description/exploit_scenario/
    /// preconditions/category/severity/confidence/recommendation per row.
    /// Explicit-only — never inferred from an output path.
    VulnFindings,
}

impl WorkspaceExportFormat {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "json" => Ok(Self::Json),
            "jsonl" | "ndjson" => Ok(Self::Jsonl),
            "sarif" => Ok(Self::Sarif),
            "csv" => Ok(Self::Csv),
            "markdown-bundle" | "markdown_bundle" | "bundle" => Ok(Self::MarkdownBundle),
            "vuln-findings" | "vuln_findings" => Ok(Self::VulnFindings),
            other => anyhow::bail!(
                "unsupported workspace findings export format {other:?}. \
                 Supported formats: json, jsonl, sarif, csv, markdown-bundle, vuln-findings"
            ),
        }
    }

    pub fn from_output_path(path: &Path) -> Result<Self> {
        if path.to_string_lossy().ends_with(".sarif.json") {
            return Ok(Self::Sarif);
        }
        match path.extension().and_then(|extension| extension.to_str()) {
            None => Ok(Self::MarkdownBundle),
            Some("json") => Ok(Self::Json),
            Some("jsonl") | Some("ndjson") => Ok(Self::Jsonl),
            Some("sarif") => Ok(Self::Sarif),
            Some("csv") => Ok(Self::Csv),
            Some(other) => anyhow::bail!(
                "unsupported workspace findings export extension .{other}. \
                 Supported extensions: .json, .jsonl, .sarif, .sarif.json, .csv. \
                 Use an extensionless directory or format=markdown-bundle for a report bundle."
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Jsonl => "jsonl",
            Self::Sarif => "sarif",
            Self::Csv => "csv",
            Self::MarkdownBundle => "markdown-bundle",
            Self::VulnFindings => "vuln-findings",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WorkspaceExportCompleteness {
    #[default]
    All,
    Open,
    Complete,
}

impl WorkspaceExportCompleteness {
    pub fn from_input(value: &str) -> Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "all" => Ok(Self::All),
            "open" | "pending" => Ok(Self::Open),
            "complete" | "completed" | "closed" => Ok(Self::Complete),
            other => anyhow::bail!(
                "unsupported workspace findings export completeness {other:?}. \
                 Supported values: all, open, complete"
            ),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Open => "open",
            Self::Complete => "complete",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceExportOptions {
    pub format: Option<WorkspaceExportFormat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub campaign_id: Option<String>,
    pub completeness: WorkspaceExportCompleteness,
    #[serde(default = "default_allow_empty_export")]
    pub allow_empty: bool,
    /// The review-yield posture the exporting session actually ran under.
    ///
    /// `#[serde(skip)]`, like `V2Config::autonomy`: this is a fact the host
    /// process observed, so tool input must not be able to assert it. A caller
    /// that could set this from JSON could stamp an export with a model id no
    /// model ever produced.
    #[serde(skip)]
    pub review_yield: Option<ReviewYieldExportProvenance>,
}

/// What the exporting session's review-yield signal was doing, recorded so a
/// reader of the export can tell whether a model was involved at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewYieldExportProvenance {
    pub mode: crate::config::ReviewYieldMode,
    /// The id of the model actually loaded, or `None` when none was. Never a
    /// placeholder: an absent id means no artifact was in play.
    pub model_id: Option<String>,
}

impl Default for WorkspaceExportOptions {
    fn default() -> Self {
        Self {
            format: None,
            campaign_id: None,
            completeness: WorkspaceExportCompleteness::All,
            allow_empty: default_allow_empty_export(),
            review_yield: None,
        }
    }
}

impl WorkspaceExportOptions {
    pub fn with_campaign(mut self, campaign_id: Option<String>) -> Self {
        self.campaign_id = campaign_id;
        self
    }

    pub fn new(format: Option<WorkspaceExportFormat>) -> Self {
        Self {
            format,
            ..Self::default()
        }
    }

    pub fn with_completeness(mut self, completeness: WorkspaceExportCompleteness) -> Self {
        self.completeness = completeness;
        self
    }

    pub fn with_allow_empty(mut self, allow_empty: bool) -> Self {
        self.allow_empty = allow_empty;
        self
    }

    pub fn with_review_yield(mut self, review_yield: Option<ReviewYieldExportProvenance>) -> Self {
        self.review_yield = review_yield;
        self
    }
}

fn default_allow_empty_export() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceFindingsExport {
    pub output_path: PathBuf,
    pub format: WorkspaceExportFormat,
    pub count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub investigation_receipt_path: Option<PathBuf>,
}
