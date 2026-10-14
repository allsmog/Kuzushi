use super::*;
pub(super) fn read_groups(
    target: &Path,
    key: &ViewHydrationKey,
    cancellation: &ViewHydrationCancellation,
) -> Option<ViewHydrationValue> {
    let ViewHydrationKey::FindingGroups(request) = key else {
        return None;
    };
    let result = kuzushi_core::WorkspaceTarget::new(target)
        .and_then(|workspace| {
            let store = kuzushi_core::FindingStore::open_read_only(workspace.findings_db_path())?;
            kuzushi_core::findings::read_finding_groups_cancellable(
                &store,
                &workspace,
                request,
                || {
                    anyhow::ensure!(!cancellation.is_canceled(), "Group read canceled");
                    Ok(())
                },
            )
        })
        .map_err(|e| format!("{e:#}"));
    Some(ViewHydrationValue::FindingGroups(result))
}
