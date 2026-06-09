use super::bower_json::bower_components;
use super::cabal::{cabal_components, is_cabal_file};
use super::cargo_manifest::cargo_target_components;
use super::conda_environment::{conda_environment_components, is_conda_environment_manifest};
use super::conanfile_txt::conanfile_components;
use super::composer_json::composer_components;
use super::cpanfile::{cpanfile_components, is_cpanfile};
use super::deno_json::deno_components;
use super::dotnet_project::{dotnet_project_components, is_dotnet_project};
use super::elm_json::{elm_components, is_elm_json};
use super::gemfile::gemfile_components;
use super::gleam_toml::gleam_components;
use super::go_mod::go_mod_components;
use super::gradle_build::{gradle_build_components, is_gradle_build};
use super::haxelib_json::haxelib_components;
use super::helm_lock::{helm_chart_components, is_helm_chart};
use super::julia_project::{is_julia_project, julia_project_components};
use super::maven_pom::maven_pom_components;
use super::mix::mix_components;
use super::nimble::{is_nimble_file, nimble_components};
use super::npm_package_json::package_components;
use super::opam::{is_opam_file, opam_components};
use super::pipfile_manifest::{is_pipfile, pipfile_components};
use super::poetry_pyproject::poetry_pyproject_components;
use super::pubspec_yaml::pubspec_components;
use super::python_dependency::python_component;
use super::r_description::{is_r_description, r_description_components};
use super::requirements::{is_requirements_manifest, requirements_components};
use super::sbt_build::sbt_components;
use super::shard_yml::{is_shard_yml, shard_components};
use super::toml_manifest::{toml_dependency_scopes, toml_value_at, toml_version};
use super::vcpkg_json::vcpkg_components;
use super::{SbomComponent, component};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub(super) fn is_dependency_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "package.json"
                    | "Cargo.toml"
                    | "pyproject.toml"
                    | "go.mod"
                    | "composer.json"
                    | "Gemfile"
                    | "gleam.toml"
                    | "pom.xml"
                    | "mix.exs"
                    | "build.sbt"
                    | "pubspec.yaml"
                    | "bower.json"
                    | "conanfile.txt"
                    | "haxelib.json"
                    | "vcpkg.json"
                    | "deno.json"
                    | "import_map.json"
            )
                || is_gradle_build(path)
                || is_requirements_manifest(name)
                || is_cabal_file(path)
                || is_conda_environment_manifest(name)
                || is_elm_json(path)
                || is_helm_chart(path)
                || is_julia_project(path)
                || is_nimble_file(path)
                || is_cpanfile(path)
                || is_opam_file(path)
                || is_pipfile(path)
                || is_r_description(path)
                || is_shard_yml(path)
                || is_dotnet_project(path)
        })
}

pub(super) fn manifest_components(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let name = path.file_name().and_then(|name| name.to_str());
    if let Some(components) = named_manifest_components(target, path, &text, name)? {
        return Ok(components);
    }
    pattern_manifest_components(target, path, &text, name)
}

fn named_manifest_components(
    target: &Path,
    path: &Path,
    text: &str,
    name: Option<&str>,
) -> Result<Option<Vec<SbomComponent>>> {
    let components = match name {
        Some("package.json") => package_components(target, path, text),
        Some("Cargo.toml") => toml_components(target, path, text, "cargo"),
        Some("pyproject.toml") => toml_components(target, path, text, "python"),
        Some("go.mod") => Ok(go_mod_components(target, path, text)),
        Some("composer.json") => composer_components(target, path, text),
        Some("Gemfile") => Ok(gemfile_components(target, path, text)),
        Some("gleam.toml") => gleam_components(target, path, text),
        Some("pom.xml") => maven_pom_components(target, path, text),
        Some("mix.exs") => Ok(mix_components(target, path, text)),
        Some("build.sbt") => Ok(sbt_components(target, path, text)),
        Some("pubspec.yaml") => pubspec_components(target, path, text),
        Some("bower.json") => bower_components(target, path, text),
        Some("conanfile.txt") => Ok(conanfile_components(target, path, text)),
        Some("haxelib.json") => haxelib_components(target, path, text),
        Some("vcpkg.json") => vcpkg_components(target, path, text),
        Some("deno.json") => deno_components(target, path, text),
        Some("import_map.json") => deno_components(target, path, text),
        _ => return Ok(None),
    }?;
    Ok(Some(components))
}

fn pattern_manifest_components(
    target: &Path,
    path: &Path,
    text: &str,
    name: Option<&str>,
) -> Result<Vec<SbomComponent>> {
    match name {
        Some(_) if is_gradle_build(path) => Ok(gradle_build_components(target, path, text)),
        Some(_) if is_cabal_file(path) => Ok(cabal_components(target, path, text)),
        Some(_) if is_cpanfile(path) => Ok(cpanfile_components(target, path, text)),
        Some(_) if is_opam_file(path) => Ok(opam_components(target, path, text)),
        Some(_) if is_elm_json(path) => elm_components(target, path, text),
        Some(_) if is_helm_chart(path) => helm_chart_components(target, path, text),
        Some(_) if is_julia_project(path) => julia_project_components(target, path, text),
        Some(_) if is_nimble_file(path) => Ok(nimble_components(target, path, text)),
        Some(_) if is_pipfile(path) => pipfile_components(target, path, text),
        Some(_) if is_r_description(path) => Ok(r_description_components(target, path, text)),
        Some(_) if is_shard_yml(path) => shard_components(target, path, text),
        Some(name) if is_conda_environment_manifest(name) => {
            conda_environment_components(target, path, text)
        }
        Some(_) if is_dotnet_project(path) => dotnet_project_components(target, path, text),
        Some(name) if is_requirements_manifest(name) => {
            Ok(requirements_components(target, path, name, text))
        }
        _ => Ok(Vec::new()),
    }
}

fn toml_components(
    target: &Path,
    path: &Path,
    text: &str,
    ecosystem: &'static str,
) -> Result<Vec<SbomComponent>> {
    let value: toml::Value = toml::from_str(text).context("sbom-scan: parse TOML manifest")?;
    let scopes = toml_dependency_scopes(ecosystem);
    let mut components = scopes
        .iter()
        .flat_map(|scope| {
            toml_dependency_entries(toml_value_at(&value, scope), target, path, ecosystem, scope)
        })
        .collect::<Vec<_>>();
    if ecosystem == "python" {
        components.extend(poetry_pyproject_components(target, path, &value));
    } else if ecosystem == "cargo" {
        components.extend(cargo_target_components(target, path, &value));
    }
    Ok(components)
}

fn toml_dependency_entries(
    value: Option<&toml::Value>,
    target: &Path,
    path: &Path,
    ecosystem: &str,
    scope: &str,
) -> Vec<SbomComponent> {
    if ecosystem == "python" && (scope.contains('.') || scope == "dependency-groups") {
        return python_dependency_entries(value, target, path, scope);
    }
    value
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|deps| deps.iter())
        .map(|(name, value)| component(target, path, ecosystem, scope, name, toml_version(value)))
        .collect()
}

fn python_dependency_entries(
    value: Option<&toml::Value>,
    target: &Path,
    path: &Path,
    scope: &str,
) -> Vec<SbomComponent> {
    if matches!(scope, "project.optional-dependencies" | "dependency-groups") {
        return python_optional_dependency_entries(value, target, path, scope);
    }
    value
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(|raw| python_component(target, path, scope, raw))
        .collect()
}

fn python_optional_dependency_entries(
    value: Option<&toml::Value>,
    target: &Path,
    path: &Path,
    scope: &str,
) -> Vec<SbomComponent> {
    value
        .and_then(toml::Value::as_table)
        .into_iter()
        .flat_map(|groups| groups.iter())
        .flat_map(|(group, deps)| python_group_dependencies(deps, target, path, scope, group))
        .collect()
}

fn python_group_dependencies(
    deps: &toml::Value,
    target: &Path,
    path: &Path,
    scope: &str,
    group: &str,
) -> Vec<SbomComponent> {
    deps.as_array()
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .map(|raw| python_component(target, path, &format!("{scope}.{group}"), raw))
        .collect()
}
