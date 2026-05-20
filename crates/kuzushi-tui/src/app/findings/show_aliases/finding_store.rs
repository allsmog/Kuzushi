use super::*;

impl ShellApp {
    pub(crate) fn open_store(&mut self) -> Result<FindingStore> {
        // workspace_for_target errors when self.target is None — bug-bounty
        // scope discipline requires the operator to opt into a target
        // explicitly. We canonicalize self.target to the resolved root so
        // subsequent reads are stable, but only when a target was already
        // supplied; we never write a value the operator did not provide.
        let (workspace, store) = open_finding_store_for_target(self.target.as_ref())?;
        let resolved = workspace.root().to_path_buf();
        if self.target.as_deref() != Some(resolved.as_path()) {
            self.target = Some(resolved);
        }
        Ok(store)
    }

    pub(crate) fn current_workspace(&self) -> Result<WorkspaceTarget> {
        workspace_for_target(self.target.as_ref())
    }
}
