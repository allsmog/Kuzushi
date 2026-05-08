use super::*;

impl ShellApp {
    pub(crate) fn open_store(&mut self) -> Result<FindingStore> {
        let (workspace, store) = open_finding_store_for_target(self.target.as_ref())?;
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
        Ok(store)
    }

    pub(crate) fn current_workspace(&self) -> Result<WorkspaceTarget> {
        workspace_for_target(self.target.as_ref())
    }
}
