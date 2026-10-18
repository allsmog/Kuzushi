use crate::ui_view_models::{dfd_selected_item, DfdLinkState, DfdModel, DfdSelected};
use anyhow::{ensure, Context, Result};
use std::collections::BTreeSet;
use std::path::{Component, Path};

const MAX_EVIDENCE_PATHS: usize = 256;

pub(super) struct DfdScanSelection {
    pub(super) label: String,
    pub(super) paths: Vec<String>,
}

impl DfdScanSelection {
    pub(super) fn from_model(
        target: &Path,
        model: &DfdModel,
        selection: usize,
        context_row: Option<usize>,
    ) -> Result<Self> {
        ensure!(
            model.empty_hint.is_none(),
            "No diagram source is available. Inspect a saved context revision first."
        );
        ensure!(
            model.link_state == DfdLinkState::Complete,
            "Rebuild linked context before planning a scan from its evidence."
        );
        let label = selected_label(model, selection).context("Select a diagram element first.")?;
        let paths = model.file_paths_for_selection(selection, context_row);
        ensure!(
            !paths.is_empty(),
            "Select a component or context row with repository file evidence."
        );
        ensure!(paths.len() <= MAX_EVIDENCE_PATHS, "This selection exceeds 256 evidence paths. Select a smaller context row or review repository scopes separately.");
        let paths = paths
            .iter()
            .map(|path| literal_path(target, path))
            .collect::<Result<BTreeSet<_>>>()?;
        Ok(Self {
            label,
            paths: paths.into_iter().collect(),
        })
    }
}

fn selected_label(model: &DfdModel, selection: usize) -> Option<String> {
    Some(match dfd_selected_item(model, selection)? {
        DfdSelected::Node(node) => format!("{} ({})", node.name, node.key),
        DfdSelected::Flow(flow) => format!("{} → {} ({})", flow.from, flow.to, flow.key),
        DfdSelected::Boundary(boundary) => format!("{} ({})", boundary.name, boundary.key),
    })
}

fn literal_path(target: &Path, evidence: &str) -> Result<String> {
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
        _ => anyhow::bail!(
            "Evidence path contains traversal or a filesystem root. No scan plan opened."
        ),
    }
}

#[cfg(test)]
mod tests;
