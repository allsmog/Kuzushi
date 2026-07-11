use super::toml_manifest::toml_value_at;
use super::{component, SbomComponent};
use std::path::Path;

const PYTHON_RUNTIME_KEY: &str = "python";

pub(super) fn poetry_pyproject_components(
    target: &Path,
    path: &Path,
    value: &toml::Value,
) -> Vec<SbomComponent> {
    let mut components = dependency_table_components(
        target,
        path,
        "tool.poetry.dependencies",
        toml_value_at(value, "tool.poetry.dependencies"),
    );
    components.extend(dependency_table_components(
        target,
        path,
        "tool.poetry.dev-dependencies",
        toml_value_at(value, "tool.poetry.dev-dependencies"),
    ));
    components.extend(poetry_group_components(target, path, value));
    components
}

fn poetry_group_components(target: &Path, path: &Path, value: &toml::Value) -> Vec<SbomComponent> {
    toml_value_at(value, "tool.poetry.group")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|groups| groups.iter())
        .flat_map(|(group, group_value)| {
            poetry_group_dependencies(target, path, group, group_value)
        })
        .collect()
}

fn poetry_group_dependencies(
    target: &Path,
    path: &Path,
    group: &str,
    value: &toml::Value,
) -> Vec<SbomComponent> {
    dependency_table_components(
        target,
        path,
        &format!("tool.poetry.group.{group}.dependencies"),
        value.get("dependencies"),
    )
}

fn dependency_table_components(
    target: &Path,
    path: &Path,
    scope: &str,
    value: Option<&toml::Value>,
) -> Vec<SbomComponent> {
    value
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|deps| deps.iter())
        .filter(|(name, _)| name.as_str() != PYTHON_RUNTIME_KEY)
        .map(|(name, value)| {
            component(
                target,
                path,
                "python",
                scope,
                name,
                dependency_version(value),
            )
        })
        .collect()
}

fn dependency_version(value: &toml::Value) -> Option<&str> {
    value
        .as_str()
        .or_else(|| value.as_table()?.get("version")?.as_str())
}
