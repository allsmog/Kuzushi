use super::*;

pub(super) fn apply(
    draft: &mut ScanScopeDraft,
    id: &str,
    children: Vec<ProposedScanScope>,
    inventory: &RepositoryInventory,
) -> Result<()> {
    anyhow::ensure!(
        children.len() >= 2,
        "a split needs at least two child scopes"
    );
    let index = primary_index(draft, id)?;
    let parent = &draft.scopes[index];
    anyhow::ensure!(
        !children.iter().any(|child| child.id == id),
        "split children need new ids"
    );
    let files = &inventory
        .inspection
        .as_ref()
        .context("inventory membership is unavailable")?
        .files;
    let parent_files = members(parent, files);
    let child_files = children
        .iter()
        .flat_map(|child| members(child, files))
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        parent_files == child_files,
        "split must preserve every parent file without adding files outside its boundary"
    );
    let ids = children
        .iter()
        .map(|child| child.id.clone())
        .collect::<Vec<_>>();
    draft.scopes.splice(index..=index, children);
    rewrite_dependencies(draft, id, &ids);
    Ok(())
}

fn members<'a>(scope: &ProposedScanScope, files: &'a [String]) -> BTreeSet<&'a str> {
    files
        .iter()
        .filter(|file| scope.paths.iter().any(|path| covers(path, file)))
        .map(String::as_str)
        .collect()
}

fn rewrite_dependencies(draft: &mut ScanScopeDraft, parent: &str, children: &[String]) {
    for scope in draft.scopes.iter_mut().chain(draft.shared_scope.iter_mut()) {
        let ids = scope
            .shared_dependencies
            .iter()
            .flat_map(|id| {
                if id == parent {
                    children.to_vec()
                } else {
                    vec![id.clone()]
                }
            })
            .filter(|id| id != &scope.id)
            .collect::<BTreeSet<_>>();
        scope.shared_dependencies = ids.into_iter().collect();
    }
}
