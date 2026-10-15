use super::*;

pub(super) fn create(draft: &mut ScanScopeDraft, source_id: &str, shared_id: String) -> Result<()> {
    anyhow::ensure!(draft.shared_scope.is_none(),
        "Shared context already exists. Edit it or remove it explicitly before choosing another boundary.");
    let mut shared = draft
        .scopes
        .iter()
        .find(|scope| scope.id == source_id)
        .cloned()
        .context("Choose a primary boundary to supply shared context")?;
    shared.id = shared_id;
    shared.name = "Shared context".into();
    draft.shared_scope = Some(shared);
    draft.shared_discovery = false;
    Ok(())
}

pub(super) fn remove(draft: &mut ScanScopeDraft) -> Result<()> {
    let id = &draft
        .shared_scope
        .as_ref()
        .context("No shared context is selected")?
        .id;
    anyhow::ensure!(!draft.scopes.iter().any(|scope| scope.shared_dependencies.contains(id)),
        "A primary boundary references this shared scope. Edit its dependencies before removing shared context.");
    draft.shared_scope = None;
    draft.shared_discovery = false;
    Ok(())
}
