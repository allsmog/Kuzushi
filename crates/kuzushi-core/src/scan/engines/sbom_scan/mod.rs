use crate::scan::ScanCancellation;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::read_dir;
use std::path::{Path, PathBuf};

#[cfg(test)]
mod tests;

mod bower_json;
mod bun_lock;
mod cabal;
mod cargo_lock;
mod cargo_manifest;
mod cartfile_resolved;
mod composer_json;
mod composer_lock;
mod conanfile_txt;
mod conda_environment;
mod cpanfile;
mod cyclonedx;
mod deno_json;
mod deno_lock;
mod dependency_graph;
mod dotnet_project;
mod edge_readers;
mod elm_json;
mod gemfile;
mod gemfile_lock;
mod gleam_toml;
mod go_mod;
mod go_sum;
mod gradle_build;
mod gradle_lock;
mod haxelib_json;
mod helm_lock;
mod julia_project;
mod lockfile;
mod lockfile_components;
mod manifest;
mod maven_pom;
mod mix;
mod nimble;
mod npm_lock;
mod npm_package_json;
mod nuget_lock;
mod opam;
mod pipfile_lock;
mod pipfile_manifest;
mod pnpm_lock;
mod podfile_lock;
mod poetry_lock;
mod poetry_pyproject;
mod pubspec_lock;
mod pubspec_yaml;
mod purl;
mod pyproject_toml;
mod python_dependency;
mod r_description;
mod renv_lock;
mod report;
mod requirements;
mod sbt_build;
mod shard_yml;
mod spdx;
mod swift_resolved;
mod target;
mod toml_manifest;
mod uv_lock;
mod vcpkg_json;
mod yarn_lock;

use dependency_graph::collect_dependency_edges;
use lockfile::collect_lockfiles;
use lockfile_components::collect_lockfile_components;

mod bounded_fs {
    use std::io;
    use std::path::Path;

    pub(super) use std::fs::read_dir;

    const MAX_SBOM_INPUT_BYTES: usize = 64 * 1024 * 1024;

    pub(super) fn read_to_string(path: impl AsRef<Path>) -> io::Result<String> {
        crate::bounded_file::read_utf8_text(path.as_ref(), MAX_SBOM_INPUT_BYTES)
    }

    pub(super) fn read(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
        crate::bounded_file::read_regular_bytes(path.as_ref(), MAX_SBOM_INPUT_BYTES)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomComponent {
    pub name: String,
    pub version: Option<String>,
    pub package_url: Option<String>,
    pub ecosystem: String,
    pub manifest_path: String,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomScanReport {
    pub target: String,
    pub manifests_scanned: usize,
    pub lockfiles: Vec<SbomLockfile>,
    pub dependencies: Vec<SbomDependencyEdge>,
    pub components: Vec<SbomComponent>,
    pub by_ecosystem: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomDependencyEdge {
    pub from: String,
    pub to: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SbomLockfile {
    pub path: String,
    pub sha256: String,
}

pub fn scan_sbom(target: &Path, cancellation: &ScanCancellation) -> Result<SbomScanReport> {
    target::ensure_directory(target)?;
    let mut manifests = Vec::new();
    collect_manifests(target, &mut manifests, cancellation)?;
    let lockfiles = collect_lockfiles(target, cancellation)?;
    let dependencies = collect_dependency_edges(target, cancellation)?;
    let mut components = manifests
        .iter()
        .map(|path| manifest::manifest_components(target, path))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    components.extend(collect_lockfile_components(target, cancellation)?);
    components.sort_by_key(report::component_sort_key);
    components.dedup();
    Ok(SbomScanReport {
        target: target.display().to_string(),
        manifests_scanned: manifests.len(),
        lockfiles,
        dependencies,
        by_ecosystem: report::ecosystem_counts(&components),
        components,
    })
}

fn collect_manifests(
    dir: &Path,
    manifests: &mut Vec<PathBuf>,
    cancellation: &ScanCancellation,
) -> Result<()> {
    if cancellation.is_cancelled() {
        anyhow::bail!("sbom-scan scan cancelled");
    }
    for entry in read_dir(dir).with_context(|| format!("sbom-scan: read {}", dir.display()))? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let path = entry.path();
        if file_type.is_dir() && !target::ignored_dir(&path) {
            collect_manifests(&path, manifests, cancellation)?;
        } else if file_type.is_file() && manifest::is_dependency_manifest(&path) {
            manifests.push(path);
        }
    }
    manifests.sort();
    Ok(())
}

pub(super) fn component(
    target: &Path,
    path: &Path,
    ecosystem: &str,
    scope: &str,
    name: &str,
    version: Option<&str>,
) -> SbomComponent {
    SbomComponent {
        name: name.to_string(),
        version: version.map(str::to_string),
        package_url: purl::package_url(ecosystem, name, version),
        ecosystem: ecosystem.to_string(),
        manifest_path: relative_display(target, path),
        scope: scope.to_string(),
    }
}

fn relative_display(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
