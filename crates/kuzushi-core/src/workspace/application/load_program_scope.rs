use super::*;
use crate::workspace::domain::ProgramScope;

const SCOPE_FILE_NAME: &str = "scope.toml";
const PROGRAM_SCOPE_SCAFFOLD: &str = r#"# Kuzushi program scope.
# Empty lists are a no-op. Add only assets you are authorized to test.
#
# Examples:
#   hosts = ["*.example.com", "api.example.net"]
#   cidrs = ["10.0.0.0/8"]

[in_scope]
hosts = []
cidrs = []

[out_of_scope]
hosts = []
cidrs = []
"#;

/// Load the `<workspace>/.kuzushi/scope.toml` bug-bounty scope file
/// when present. Returns `Ok(None)` if the file is absent so callers
/// can treat "no scope" as the no-op default. Parse errors surface as
/// `Err` — callers must refuse to run rather than silently ignore a
/// malformed scope.
pub fn load_program_scope(workspace: &WorkspaceTarget) -> Result<Option<ProgramScope>> {
    let path = program_scope_path(workspace);
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let scope = ProgramScope::parse(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(Some(scope))
}

pub fn write_program_scope_scaffold(workspace: &WorkspaceTarget) -> Result<std::path::PathBuf> {
    let path = program_scope_path(workspace);
    if path.exists() {
        anyhow::bail!(
            "{} already exists. Edit it directly, or remove it before reinitializing.",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Could not create {}", parent.display()))?;
    }
    std::fs::write(&path, PROGRAM_SCOPE_SCAFFOLD)
        .with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn program_scope_path(workspace: &WorkspaceTarget) -> std::path::PathBuf {
    workspace.root().join(".kuzushi").join(SCOPE_FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn returns_none_when_scope_file_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let scope = load_program_scope(&workspace).unwrap();
        assert!(scope.is_none());
    }

    #[test]
    fn parses_present_scope_file() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let kuzushi = tmp.path().join(".kuzushi");
        fs::create_dir_all(&kuzushi).unwrap();
        fs::write(
            kuzushi.join("scope.toml"),
            r#"
            [in_scope]
            hosts = ["*.example.com"]
            "#,
        )
        .unwrap();

        let scope = load_program_scope(&workspace).unwrap().unwrap();
        assert!(!scope.is_empty());
    }

    #[test]
    fn malformed_scope_file_surfaces_as_error() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();
        let kuzushi = tmp.path().join(".kuzushi");
        fs::create_dir_all(&kuzushi).unwrap();
        fs::write(kuzushi.join("scope.toml"), "[in_scope]\nhosts = [\"]\n").unwrap();

        let err = load_program_scope(&workspace).unwrap_err().to_string();
        assert!(err.contains("Could not parse"));
    }

    #[test]
    fn writes_empty_scope_scaffold_without_enforcing_scope() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        let path = write_program_scope_scaffold(&workspace).unwrap();
        assert_eq!(path, workspace.root().join(".kuzushi/scope.toml"));
        let loaded = load_program_scope(&workspace).unwrap().unwrap();

        assert!(loaded.is_empty());
        assert!(fs::read_to_string(path).unwrap().contains("hosts = []"));
    }

    #[test]
    fn scope_scaffold_refuses_to_overwrite_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        let workspace = WorkspaceTarget::new(tmp.path()).unwrap();

        write_program_scope_scaffold(&workspace).unwrap();
        let err = write_program_scope_scaffold(&workspace)
            .unwrap_err()
            .to_string();

        assert!(err.contains("already exists"));
    }
}
