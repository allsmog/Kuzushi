use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceStatus {
    pub root: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub findings_db: Option<PathBuf>,
    pub findings_count: Option<usize>,
    pub last_export: Option<PathBuf>,
    pub status: String,
}

pub fn workspace_status_for_target(
    target: Option<&Path>,
    last_export: Option<PathBuf>,
) -> WorkspaceStatus {
    let Some(target) = target else {
        return missing_workspace_status(last_export);
    };
    match WorkspaceTarget::new(target) {
        Ok(workspace) => ready_workspace_status(&workspace, last_export),
        Err(error) => WorkspaceStatus {
            root: None,
            state_dir: None,
            findings_db: None,
            findings_count: None,
            last_export,
            status: format!("{error}. Next: scan <target>"),
        },
    }
}

fn missing_workspace_status(last_export: Option<PathBuf>) -> WorkspaceStatus {
    WorkspaceStatus {
        root: None,
        state_dir: None,
        findings_db: None,
        findings_count: None,
        last_export,
        status: "no active workspace. Next: scan <target> or start shell with --target ."
            .to_string(),
    }
}

fn ready_workspace_status(
    workspace: &WorkspaceTarget,
    last_export: Option<PathBuf>,
) -> WorkspaceStatus {
    let findings_db = workspace.findings_db_path();
    let findings_count = workspace_findings_count(&findings_db);
    let count_label = findings_count
        .map(|count| count.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    WorkspaceStatus {
        root: Some(workspace.root().to_path_buf()),
        state_dir: Some(workspace.state_dir()),
        findings_db: Some(findings_db),
        findings_count,
        last_export,
        status: format!(
            "workspace ready; {count_label} finding(s). Next: workspace export findings <path>.json"
        ),
    }
}

fn workspace_findings_count(findings_db: &Path) -> Option<usize> {
    if !findings_db.exists() {
        return Some(0);
    }
    FindingStore::open(findings_db)
        .and_then(|store| store.list_findings(FindingListFilter::MAX_LIMIT))
        .map(|findings| findings.len())
        .ok()
}
