use super::bun_lock::{bun_lock_components, is_bun_lock};
use super::cargo_lock::{cargo_lock_components, is_cargo_lock};
use super::cartfile_resolved::{cartfile_resolved_components, is_cartfile_resolved};
use super::composer_lock::{composer_lock_components, is_composer_lock};
use super::deno_lock::{deno_lock_components, is_deno_lock};
use super::gemfile_lock::{gemfile_lock_components, is_gemfile_lock};
use super::go_sum::{go_sum_components, is_go_sum};
use super::gradle_lock::{gradle_lock_components, is_gradle_lock};
use super::helm_lock::{helm_lock_components, is_helm_lock};
use super::mix::{is_mix_lock, mix_lock_components};
use super::npm_lock::{is_package_lock, package_lock_components};
use super::nuget_lock::{is_nuget_lock, nuget_lock_components};
use super::pipfile_lock::{is_pipfile_lock, pipfile_lock_components};
use super::pnpm_lock::{is_pnpm_lock, pnpm_lock_components};
use super::podfile_lock::{is_podfile_lock, podfile_lock_components};
use super::poetry_lock::{is_poetry_lock, poetry_lock_components};
use super::pubspec_lock::{is_pubspec_lock, pubspec_lock_components};
use super::renv_lock::{is_renv_lock, renv_lock_components};
use super::swift_resolved::{is_swift_resolved, swift_resolved_components};
use super::uv_lock::{is_uv_lock, uv_lock_components};
use super::yarn_lock::{is_yarn_lock, yarn_lock_components};
use super::SbomComponent;
use anyhow::Result;
use std::path::{Path, PathBuf};

type LockfileDetector = fn(&Path) -> bool;
type LockfileComponentReader = fn(&Path, &Path) -> Result<Vec<SbomComponent>>;

const LOCKFILE_COMPONENT_READERS: &[(LockfileDetector, LockfileComponentReader)] = &[
    (is_bun_lock, bun_lock_components),
    (is_cargo_lock, cargo_lock_components),
    (is_cartfile_resolved, cartfile_resolved_components),
    (is_composer_lock, composer_lock_components),
    (is_deno_lock, deno_lock_components),
    (is_gemfile_lock, gemfile_lock_components),
    (is_go_sum, go_sum_components),
    (is_gradle_lock, gradle_lock_components),
    (is_helm_lock, helm_lock_components),
    (is_mix_lock, mix_lock_components),
    (is_package_lock, package_lock_components),
    (is_nuget_lock, nuget_lock_components),
    (is_pipfile_lock, pipfile_lock_components),
    (is_podfile_lock, podfile_lock_components),
    (is_pnpm_lock, pnpm_lock_components),
    (is_poetry_lock, poetry_lock_components),
    (is_pubspec_lock, pubspec_lock_components),
    (is_renv_lock, renv_lock_components),
    (is_swift_resolved, swift_resolved_components),
    (is_uv_lock, uv_lock_components),
    (is_yarn_lock, yarn_lock_components),
];

pub(super) fn collect_lockfile_components(
    target: &Path,
    files: &[PathBuf],
) -> Result<Vec<SbomComponent>> {
    files.iter().try_fold(Vec::new(), |mut components, path| {
        components.extend(lockfile_components_for_path(target, path)?);
        Ok(components)
    })
}

fn lockfile_components_for_path(target: &Path, path: &Path) -> Result<Vec<SbomComponent>> {
    LOCKFILE_COMPONENT_READERS
        .iter()
        .find(|(matches, _)| matches(path))
        .map_or_else(|| Ok(Vec::new()), |(_, read)| read(target, path))
}
