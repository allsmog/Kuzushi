use super::*;

pub(super) fn apply(draft: &mut ScanScopeDraft, from: &str, into: &str) -> Result<()> {
    anyhow::ensure!(from != into, "choose two different scopes to merge");
    let from_index = primary_index(draft, from)?;
    primary_index(draft, into)?;
    let source = draft.scopes.remove(from_index);
    let into_index = primary_index(draft, into)?;
    let target = &mut draft.scopes[into_index];
    target.paths.extend(source.paths);
    target.paths.sort();
    target.paths.dedup();
    target
        .shared_dependencies
        .extend(source.shared_dependencies);
    target.open_questions.extend(source.open_questions);
    target.rationale = format!(
        "Operator merged {} into {}. {} {}",
        source.name, target.name, target.rationale, source.rationale
    );
    rewrite_dependencies(draft, from, into);
    Ok(())
}

fn rewrite_dependencies(draft: &mut ScanScopeDraft, from: &str, into: &str) {
    for scope in draft.scopes.iter_mut().chain(draft.shared_scope.iter_mut()) {
        let dependencies = scope
            .shared_dependencies
            .iter()
            .map(|id| {
                if id == from {
                    into.to_string()
                } else {
                    id.clone()
                }
            })
            .filter(|id| id != &scope.id)
            .collect::<BTreeSet<_>>();
        scope.shared_dependencies = dependencies.into_iter().collect();
    }
}
