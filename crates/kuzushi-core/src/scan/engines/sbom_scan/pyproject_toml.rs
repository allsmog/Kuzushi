use super::bounded_fs as fs;
use super::python_dependency::python_dependency_name;
use super::toml_manifest::toml_value_at;
use super::{relative_display, SbomDependencyEdge};
use anyhow::{Context, Result};
use std::path::Path;

const PYTHON_RUNTIME_KEY: &str = "python";

pub(super) fn is_pyproject_toml(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "pyproject.toml")
}

pub(super) fn pyproject_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse pyproject.toml")?;
    let source = relative_display(target, path);
    Ok(python_dependency_names(&value)
        .into_iter()
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn python_dependency_names(value: &toml::Value) -> Vec<String> {
    let mut names = pep621_dependency_names(value);
    names.extend(poetry_dependency_names(value));
    names
}

fn pep621_dependency_names(value: &toml::Value) -> Vec<String> {
    let mut names = array_dependency_names(toml_value_at(value, "project.dependencies"));
    names.extend(grouped_array_dependency_names(toml_value_at(
        value,
        "project.optional-dependencies",
    )));
    names.extend(grouped_array_dependency_names(toml_value_at(
        value,
        "dependency-groups",
    )));
    names
}

fn poetry_dependency_names(value: &toml::Value) -> Vec<String> {
    let mut names = table_dependency_names(toml_value_at(value, "tool.poetry.dependencies"));
    names.extend(table_dependency_names(toml_value_at(
        value,
        "tool.poetry.dev-dependencies",
    )));
    names.extend(poetry_group_dependency_names(value));
    names
}

fn poetry_group_dependency_names(value: &toml::Value) -> Vec<String> {
    toml_value_at(value, "tool.poetry.group")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|groups| groups.values())
        .flat_map(|group| table_dependency_names(group.get("dependencies")))
        .collect()
}

fn grouped_array_dependency_names(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|groups| groups.values())
        .flat_map(|dependencies| array_dependency_names(Some(dependencies)))
        .collect()
}

fn array_dependency_names(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(python_dependency_name)
        .filter(|name| !name.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn table_dependency_names(value: Option<&toml::Value>) -> Vec<String> {
    value
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|dependencies| dependencies.keys())
        .filter(|name| name.as_str() != PYTHON_RUNTIME_KEY)
        .map(ToString::to_string)
        .collect()
}
