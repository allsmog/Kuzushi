use super::*;
use crate::workspace::domain::ProgramScope;

const SCOPE_FILE_NAME: &str = "scope.toml";

/// Load the `<workspace>/.kuzushi/scope.toml` bug-bounty scope file
/// when present. Returns `Ok(None)` if the file is absent so callers
/// can treat "no scope" as the no-op default. Parse errors surface as
/// `Err` — callers must refuse to run rather than silently ignore a
/// malformed scope.
pub fn load_program_scope(workspace: &WorkspaceTarget) -> Result<Option<ProgramScope>> {
    let path = scope_path(workspace);
    if !path.exists() {
        return Ok(None);
    }
    let body = std::fs::read_to_string(&path)
        .with_context(|| format!("Could not read {}", path.display()))?;
    let scope = ProgramScope::parse(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(Some(scope))
}

fn scope_path(workspace: &WorkspaceTarget) -> std::path::PathBuf {
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
}
