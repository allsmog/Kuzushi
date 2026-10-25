use crate::app::dfd_evidence::relative_file_path;
use crate::ui_view_models::{dfd_selected_item, DfdLinkState, DfdModel, DfdSelected};
use anyhow::{ensure, Context, Result};
use std::collections::BTreeSet;
use std::path::Path;

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
            .map(|path| relative_file_path(target, path))
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

#[cfg(test)]
mod tests;
