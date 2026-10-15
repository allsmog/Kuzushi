use super::bounded_regular_files::{
    collect_regular_files, FileLimitBehavior, RegularFileWalkOptions,
};
use crate::scan::ScanCancellation;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
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
mod input_store;
mod inspection;
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
mod options;
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

use input_store::SbomInputs;
pub use inspection::{
    InspectedSbomReport, SbomInputInspection, SbomInputReceipt, SbomInspectionError,
};
pub use options::{
    SbomScanOptions, DEFAULT_SBOM_TOTAL_BYTES, MAX_SBOM_FILE_BYTES, MAX_SBOM_TOTAL_BYTES,
};

use dependency_graph::collect_dependency_edges;
use lockfile::collect_lockfiles;
use lockfile_components::collect_lockfile_components;

mod bounded_fs {
    use super::SbomInputs;
    use std::io;
    use std::path::Path;

    pub(super) fn read_to_string(
        target: &SbomInputs,
        path: impl AsRef<Path>,
    ) -> io::Result<String> {
        String::from_utf8(target.bytes(path.as_ref())?.as_ref().clone())
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
    }

    pub(super) fn read(
        target: &SbomInputs,
        path: impl AsRef<Path>,
    ) -> io::Result<std::sync::Arc<Vec<u8>>> {
        target.bytes(path.as_ref())
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
    Ok(scan_sbom_with_options(target, cancellation, &SbomScanOptions::default())?.report)
}

pub fn scan_sbom_with_options(
    target: &Path,
    cancellation: &ScanCancellation,
    options: &SbomScanOptions,
) -> Result<InspectedSbomReport> {
    options.validate()?;
    target::ensure_directory(target)?;
    let inputs = SbomInputs::new(target, options.clone(), cancellation.clone())?;
    let result = scan_captured_inputs(&inputs, cancellation).and_then(|mut report| {
        inputs.verify_root()?;
        report.target = target.display().to_string();
        Ok(report)
    });
    let inspection = inputs.inspection();
    match result {
        Ok(report) => Ok(InspectedSbomReport { report, inspection }),
        Err(error) => Err(SbomInspectionError {
            message: format!("{error:#}"),
            inspection,
        }
        .into()),
    }
}

fn scan_captured_inputs(
    target: &SbomInputs,
    cancellation: &ScanCancellation,
) -> Result<SbomScanReport> {
    let files = collect_regular_files(target, cancellation, sbom_walk_options())?.files;
    ensure_scan_active(cancellation)?;
    let manifests = collect_manifests(&files);
    ensure_scan_active(cancellation)?;
    let lockfiles = collect_lockfiles(target, &files)?;
    ensure_scan_active(cancellation)?;
    let dependencies = collect_dependency_edges(target, &files)?;
    ensure_scan_active(cancellation)?;
    let mut components = manifests
        .iter()
        .map(|path| manifest::manifest_components(target, path))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    ensure_scan_active(cancellation)?;
    components.extend(collect_lockfile_components(target, &files)?);
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

fn ensure_scan_active(cancellation: &ScanCancellation) -> Result<()> {
    cancellation.wait_if_paused();
    anyhow::ensure!(!cancellation.is_cancelled(), "sbom-scan scan cancelled");
    Ok(())
}

fn sbom_walk_options() -> RegularFileWalkOptions {
    RegularFileWalkOptions {
        operation: "sbom-scan",
        max_entries: 100_000,
        max_files: 50_000,
        max_depth: 64,
        file_limit: FileLimitBehavior::Error,
        ignored_dir: target::ignored_dir,
    }
}

fn collect_manifests(files: &[PathBuf]) -> Vec<PathBuf> {
    files
        .iter()
        .filter(|path| manifest::is_dependency_manifest(path))
        .cloned()
        .collect()
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
