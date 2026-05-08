use super::*;

impl ShellApp {
    pub(crate) fn open_store(&mut self) -> Result<FindingStore> {
        let workspace = self.current_workspace()?;
        let resolved = workspace.root().to_path_buf();
        // Surface the implicit target assignment so the operator isn't
        // surprised by `target none` flipping to a real path the moment
        // they type `findings`. We log on the first transition only.
        if self.target.as_deref() != Some(resolved.as_path()) {
            self.log(
                "target",
                format!("set to {} (implied from cwd)", resolved.display()),
            );
        }
        self.target = Some(resolved);
        FindingStore::open(workspace.findings_db_path())
    }

    pub(crate) fn current_workspace(&self) -> Result<WorkspaceTarget> {
        let target = self.target.clone().unwrap_or_else(|| PathBuf::from("."));
        WorkspaceTarget::new(target)
    }

    pub(crate) fn explicit_workspace(&self) -> Result<WorkspaceTarget> {
        let Some(target) = self.target.clone() else {
            anyhow::bail!(
                "workspace export requires an active workspace. Next: scan <target> or start shell with --target ."
            );
        };
        WorkspaceTarget::new(target)
    }
}
