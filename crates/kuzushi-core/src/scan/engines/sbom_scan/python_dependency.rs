use super::{component, SbomComponent};
use std::path::Path;

pub(super) fn python_dependency_name(raw: &str) -> &str {
    raw.split(['=', '<', '>', '~', '!', ';', '['])
        .next()
        .unwrap_or(raw)
        .split_whitespace()
        .next()
        .unwrap_or(raw)
        .trim()
}

pub(super) fn python_component(
    target: &Path,
    path: &Path,
    scope: &str,
    raw: &str,
) -> SbomComponent {
    let name = python_dependency_name(raw);
    component(target, path, "python", scope, name, Some(raw.trim()))
}
