use super::*;

pub(super) fn validate(draft: &ScanScopeDraft, files: &BTreeSet<&str>) -> Result<()> {
    anyhow::ensure!(
        draft.schema_version == 1,
        "unsupported scan scope draft schema"
    );
    anyhow::ensure!(
        !draft.scopes.is_empty(),
        "at least one primary scope is required"
    );
    anyhow::ensure!(
        draft.scopes.len() <= MAX_PRIMARY_SCOPES,
        "at most eight primary scopes are allowed"
    );
    anyhow::ensure!(
        draft.exclusions.len() <= MAX_EXCLUSIONS,
        "too many scope exclusions"
    );
    anyhow::ensure!(
        !draft.shared_discovery || draft.shared_scope.is_some(),
        "shared discovery requires a shared scope"
    );
    let ids = unique_scope_ids(draft)?;
    for scope in draft.groups() {
        validate_group(scope, files, &ids)?;
    }
    validate_exclusions(&draft.exclusions, files)
}

fn unique_scope_ids(draft: &ScanScopeDraft) -> Result<BTreeSet<&str>> {
    let mut ids = BTreeSet::new();
    for scope in draft.groups() {
        anyhow::ensure!(
            valid_id(&scope.id),
            "scope ids must be portable identifiers of at most 64 bytes"
        );
        anyhow::ensure!(
            ids.insert(scope.id.as_str()),
            "duplicate scope id {}",
            scope.id
        );
    }
    Ok(ids)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn validate_group(
    scope: &ProposedScanScope,
    files: &BTreeSet<&str>,
    ids: &BTreeSet<&str>,
) -> Result<()> {
    required_text(&scope.name, 160, "scope name")?;
    required_text(&scope.rationale, 2048, "scope rationale")?;
    anyhow::ensure!(
        !scope.paths.is_empty(),
        "scope {} has no membership",
        scope.id
    );
    anyhow::ensure!(
        scope.paths.len() <= MAX_SCOPE_PATHS,
        "scope {} has too many paths",
        scope.id
    );
    for path in &scope.paths {
        inventory_path(path, files)?;
    }
    validate_dependencies(scope, ids)?;
    anyhow::ensure!(
        scope.open_questions.len() <= 16,
        "too many boundary questions"
    );
    for question in &scope.open_questions {
        required_text(question, 512, "boundary question")?;
    }
    Ok(())
}

fn validate_dependencies(scope: &ProposedScanScope, ids: &BTreeSet<&str>) -> Result<()> {
    anyhow::ensure!(
        scope.shared_dependencies.len() <= 8,
        "too many shared dependencies"
    );
    for dependency in &scope.shared_dependencies {
        anyhow::ensure!(dependency != &scope.id, "a scope cannot depend on itself");
        anyhow::ensure!(
            ids.contains(dependency.as_str()),
            "unknown shared dependency {dependency}"
        );
    }
    Ok(())
}

fn validate_exclusions(exclusions: &[ScanScopeExclusion], files: &BTreeSet<&str>) -> Result<()> {
    let mut paths = BTreeSet::new();
    for exclusion in exclusions {
        inventory_path(&exclusion.path, files)?;
        required_text(&exclusion.reason, 2048, "exclusion reason")?;
        anyhow::ensure!(paths.insert(&exclusion.path), "duplicate excluded path");
    }
    Ok(())
}

fn inventory_path(path: &str, files: &BTreeSet<&str>) -> Result<()> {
    anyhow::ensure!(
        portable_path(path),
        "invalid repository-relative scope path {path:?}"
    );
    if path == "." {
        return Ok(());
    }
    anyhow::ensure!(
        files.iter().any(|member| covers(path, member)),
        "scope path is not present in inventory: {path}"
    );
    Ok(())
}

fn portable_path(path: &str) -> bool {
    if path == "." {
        return true;
    }
    if path.len() > 1024 {
        return false;
    }
    if path
        .chars()
        .any(|c| c.is_control() || matches!(c, '\\' | ':'))
    {
        return false;
    }
    path.split('/')
        .all(|segment| !matches!(segment, "" | "." | ".."))
}

fn required_text(text: &str, maximum: usize, label: &str) -> Result<()> {
    anyhow::ensure!(!text.trim().is_empty(), "{label} is required");
    anyhow::ensure!(text.len() <= maximum, "{label} is too long");
    anyhow::ensure!(
        !text.chars().any(char::is_control),
        "{label} must be a single printable line"
    );
    Ok(())
}
