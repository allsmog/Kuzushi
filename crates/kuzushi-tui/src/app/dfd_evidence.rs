//! Shared lexical containment for diagram evidence links and scoped actions.
use anyhow::{ensure, Context, Result};
use std::path::{Component, Path};

pub(super) fn relative_file_path(target: &Path, evidence: &str) -> Result<String> {
    ensure!(
        !evidence.contains("://"),
        "Evidence is not a repository path: {evidence:?}"
    );
    let path = Path::new(evidence);
    let relative = if path.is_absolute() {
        path.strip_prefix(target)
            .with_context(|| format!("Evidence is outside the repository: {evidence:?}"))?
    } else {
        path
    };
    let parts = relative
        .components()
        .map(literal_component)
        .collect::<Result<Vec<_>>>()?;
    let relative = parts.into_iter().flatten().collect::<Vec<_>>().join("/");
    ensure!(
        !relative.is_empty(),
        "Evidence must name a source path, not the repository root."
    );
    Ok(relative)
}

fn literal_component(component: Component<'_>) -> Result<Option<&str>> {
    match component {
        Component::Normal(name) => Ok(Some(name.to_str().context("Evidence path must be UTF-8.")?)),
        Component::CurDir => Ok(None),
        _ => anyhow::bail!("Evidence path contains traversal or a filesystem root."),
    }
}

#[cfg(test)]
mod tests;
