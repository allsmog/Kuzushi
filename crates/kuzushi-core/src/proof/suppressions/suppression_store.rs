use super::*;

impl Default for WhiteboxSuppressionStoreFile {
    fn default() -> Self {
        Self {
            version: 1,
            suppressions: Vec::new(),
        }
    }
}

pub fn whitebox_suppression_store_path(workspace: &WorkspaceTarget) -> PathBuf {
    workspace.state_dir().join(WHITEBOX_SUPPRESSION_STORE_NAME)
}

pub fn load_whitebox_suppressions(
    workspace: &WorkspaceTarget,
) -> Result<Vec<WhiteboxSuppressionRecord>> {
    let path = whitebox_suppression_store_path(workspace);
    if !path.exists() {
        return Ok(Vec::new());
    }
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let value: Value = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    let suppressions = if value.is_array() {
        serde_json::from_value(value)
            .with_context(|| format!("Could not parse {}", path.display()))?
    } else {
        serde_json::from_value::<WhiteboxSuppressionStoreFile>(value)
            .with_context(|| format!("Could not parse {}", path.display()))?
            .suppressions
    };
    for record in &suppressions {
        validate_whitebox_suppression(record)?;
    }
    Ok(sorted_suppressions(suppressions))
}

pub fn save_whitebox_suppressions(
    workspace: &WorkspaceTarget,
    suppressions: &[WhiteboxSuppressionRecord],
) -> Result<()> {
    workspace.ensure_state_dir()?;
    for record in suppressions {
        validate_whitebox_suppression(record)?;
    }
    let path = whitebox_suppression_store_path(workspace);
    let store = WhiteboxSuppressionStoreFile {
        version: 1,
        suppressions: sorted_suppressions(suppressions.to_vec()),
    };
    let body = format!("{}\n", serde_json::to_string_pretty(&store)?);
    fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))
}

pub fn upsert_whitebox_suppression(
    workspace: &WorkspaceTarget,
    record: WhiteboxSuppressionRecord,
) -> Result<WhiteboxSuppressionRecord> {
    validate_whitebox_suppression(&record)?;
    let mut suppressions = load_whitebox_suppressions(workspace)?;
    if let Some(existing) = suppressions
        .iter_mut()
        .find(|existing| existing.id == record.id)
    {
        *existing = record.clone();
    } else {
        suppressions.push(record.clone());
    }
    save_whitebox_suppressions(workspace, &suppressions)?;
    Ok(record)
}

pub fn build_whitebox_suppression_for_finding(
    repo_root: impl AsRef<Path>,
    finding: &Finding,
    reason: impl Into<String>,
    author: impl Into<String>,
    expires_at_unix: u64,
) -> Result<WhiteboxSuppressionRecord> {
    let created_at_unix = now_unix();
    build_whitebox_suppression_for_finding_at(
        repo_root,
        finding,
        reason,
        author,
        created_at_unix,
        expires_at_unix,
    )
}
