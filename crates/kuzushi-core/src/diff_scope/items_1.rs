use super::prelude::*;
use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffScope {
    pub files: Vec<PathBuf>,
    pub since_ref: String,
    pub include_worktree: bool,
}

impl DiffScope {
    pub fn contains_path(&self, candidate: &Path) -> bool {
        self.files.iter().any(|path| path == candidate)
    }

    pub fn contains_prefix(&self, prefix: &Path) -> bool {
        self.files.iter().any(|path| path.starts_with(prefix))
    }
}

pub fn git_diff_files(target: &Path, since_ref: &str, include_worktree: bool) -> Result<DiffScope> {
    let trimmed = since_ref.trim();
    anyhow::ensure!(
        !trimmed.is_empty(),
        "diff_scope: since_ref must be non-empty"
    );
    anyhow::ensure!(
        !trimmed
            .chars()
            .any(|c| matches!(c, '\n' | '\0' | ';' | '|' | '`')),
        "diff_scope: since_ref contains forbidden characters"
    );

    let mut cmd = Command::new("git");
    cmd.arg("-C").arg(target).arg("diff").arg("--name-only");
    if include_worktree {
        cmd.arg(trimmed);
    } else {
        cmd.arg(format!("{trimmed}...HEAD"));
    }
    cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

    let output = cmd
        .output()
        .with_context(|| format!("diff_scope: could not invoke git in {}", target.display()))?;
    if !output.status.success() {
        anyhow::bail!(
            "diff_scope: git diff failed (exit {}): {}",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "<signal>".to_string()),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout =
        String::from_utf8(output.stdout).context("diff_scope: git output was not valid UTF-8")?;
    let mut files = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect::<Vec<_>>();
    files.sort();
    files.dedup();

    Ok(DiffScope {
        files,
        since_ref: since_ref.to_string(),
        include_worktree,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WhiteboxDiffScopeReport {
    pub diff_base: String,
    pub target: String,
    pub changed_files: Vec<ChangedFile>,
    pub context: Vec<DiffContext>,
    pub finding_tags: Vec<DiffFindingTag>,
    pub fixed_findings: Vec<DiffFindingTag>,
    pub summary: DiffScopeSummary,
    pub deterministic: bool,
    pub no_remote_provider_required: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ChangedFile {
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_path: Option<String>,
    pub status: DiffFileStatus,
    pub changed_ranges: Vec<ChangedLineRange>,
    pub deleted_ranges: Vec<ChangedLineRange>,
}
