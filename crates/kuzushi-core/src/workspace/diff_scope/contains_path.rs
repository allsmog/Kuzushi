use super::*;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DiffScope {
    /// Paths named against the target the diff was taken in, sorted and
    /// deduped.
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

/// Refuse a reference git would read as something other than a revision.
///
/// A leading `-` is parsed as an option (`--output=<path>` becomes an
/// arbitrary-path write); the metacharacter check is defense in depth for
/// values echoed into diagnostics.
fn ensure_safe_since_ref(trimmed: &str) -> Result<()> {
    crate::git_rev::ensure_safe_git_rev(trimmed, "diff_scope since_ref")?;
    anyhow::ensure!(
        !trimmed.chars().any(|c| matches!(c, ';' | '|' | '`')),
        "diff_scope: since_ref contains forbidden characters"
    );
    Ok(())
}

/// `git diff` listing the names `trimmed` changed, framed so every name
/// arrives as the bytes that open the file and named against `target`.
///
/// `-z` prints each name's raw bytes followed by NUL. Without it git quotes any
/// name holding a non-ASCII byte, a quote, a backslash or a control character,
/// and a quoted name names no file on disk.
///
/// `--relative` names each file against `target` rather than the enclosing
/// repository root, which is the domain [`DiffScope::files`] declares and the
/// one its caller joins onto. It also drops changes outside `target`, which no
/// scan of `target` could reach.
fn changed_name_listing_command(target: &Path, trimmed: &str, include_worktree: bool) -> Command {
    let mut cmd = Command::new("git");
    cmd.arg("-C")
        .arg(target)
        .arg("diff")
        .arg("--name-only")
        .arg("-z")
        .arg("--relative");
    if include_worktree {
        cmd.arg(trimmed);
    } else {
        cmd.arg(format!("{trimmed}...HEAD"));
    }
    cmd
}

pub fn git_diff_files(target: &Path, since_ref: &str, include_worktree: bool) -> Result<DiffScope> {
    let trimmed = since_ref.trim();
    ensure_safe_since_ref(trimmed)?;

    let mut cmd = changed_name_listing_command(target, trimmed, include_worktree);
    let output = crate::bounded_subprocess::output(&mut cmd, "git diff")
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

    let mut files = crate::git_nul_paths::nul_separated_paths(&output.stdout, "diff_scope")?
        .into_iter()
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
    #[serde(alias = "fixedFindings")]
    pub not_seen_findings: Vec<DiffFindingTag>,
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
