use super::bower_json::{bower_edges, is_bower_json};
use super::bun_lock::{bun_lock_edges, is_bun_lock};
use super::cabal::{cabal_edges, is_cabal_file};
use super::cargo_manifest::{cargo_manifest_edges, is_cargo_manifest};
use super::cartfile_resolved::{cartfile_resolved_edges, is_cartfile_resolved};
use super::conda_environment::{conda_environment_edges, is_conda_environment_path};
use super::conanfile_txt::{conanfile_edges, is_conanfile_txt};
use super::composer_json::{composer_edges, is_composer_json};
use super::composer_lock::{composer_lock_edges, is_composer_lock};
use super::cpanfile::{cpanfile_edges, is_cpanfile};
use super::deno_json::{deno_edges, is_deno_json};
use super::deno_lock::{deno_lock_edges, is_deno_lock};
use super::dependency_graph::{
    cargo_lock_edges, go_sum_edges, is_cargo_lock, is_go_sum, is_package_lock, is_pnpm_lock,
    package_lock_edges,
};
use super::dotnet_project::{dotnet_project_edges, is_dotnet_project};
use super::elm_json::{elm_edges, is_elm_json};
use super::gemfile::{gemfile_edges, is_gemfile};
use super::gemfile_lock::{gemfile_lock_edges, is_gemfile_lock};
use super::gleam_toml::{gleam_edges, is_gleam_toml};
use super::go_mod::{go_mod_edges, is_go_mod};
use super::gradle_build::{gradle_build_edges, is_gradle_build};
use super::gradle_lock::{gradle_lock_edges, is_gradle_lock};
use super::haxelib_json::{haxelib_edges, is_haxelib_json};
use super::helm_lock::{helm_chart_edges, helm_lock_edges, is_helm_chart, is_helm_lock};
use super::julia_project::{is_julia_project, julia_project_edges};
use super::maven_pom::{is_maven_pom, maven_pom_edges};
use super::mix::{is_mix_exs, is_mix_lock, mix_edges, mix_lock_edges};
use super::nimble::{is_nimble_file, nimble_edges};
use super::npm_package_json::{is_package_json, package_edges};
use super::nuget_lock::{is_nuget_lock, nuget_lock_edges};
use super::opam::{is_opam_file, opam_edges};
use super::pipfile_manifest::{is_pipfile, pipfile_edges};
use super::pipfile_lock::{is_pipfile_lock, pipfile_lock_edges};
use super::podfile_lock::{is_podfile_lock, podfile_lock_edges};
use super::pnpm_lock::pnpm_lock_edges;
use super::poetry_lock::{is_poetry_lock, poetry_lock_edges};
use super::pyproject_toml::{is_pyproject_toml, pyproject_edges};
use super::pubspec_lock::{is_pubspec_lock, pubspec_lock_edges};
use super::pubspec_yaml::{is_pubspec_yaml, pubspec_edges};
use super::r_description::{is_r_description, r_description_edges};
use super::renv_lock::{is_renv_lock, renv_lock_edges};
use super::requirements::{is_requirements_manifest, requirements_edges};
use super::sbt_build::{is_sbt_build, sbt_edges};
use super::shard_yml::{is_shard_yml, shard_edges};
use super::swift_resolved::{is_swift_resolved, swift_resolved_edges};
use super::uv_lock::{is_uv_lock, uv_lock_edges};
use super::vcpkg_json::{is_vcpkg_json, vcpkg_edges};
use super::yarn_lock::{is_yarn_lock, yarn_lock_edges};
use super::SbomDependencyEdge;
use anyhow::Result;
use std::path::Path;

type EdgeReader = (
    fn(&Path) -> bool,
    fn(&Path, &Path) -> Result<Vec<SbomDependencyEdge>>,
);

const EDGE_READERS: &[EdgeReader] = &[
    (is_package_lock, package_lock_edges),
    (is_package_json, package_edges),
    (is_bower_json, bower_edges),
    (is_cargo_manifest, cargo_manifest_edges),
    (is_cargo_lock, cargo_lock_edges),
    (is_go_mod, go_mod_edges),
    (is_go_sum, go_sum_edges),
    (is_gradle_build, gradle_build_edges),
    (is_poetry_lock, poetry_lock_edges),
    (is_pipfile_lock, pipfile_lock_edges),
    (is_uv_lock, uv_lock_edges),
    (is_yarn_lock, yarn_lock_edges),
    (is_bun_lock, bun_lock_edges),
    (is_pnpm_lock, pnpm_lock_edges),
    (is_composer_json, composer_edges),
    (is_composer_lock, composer_lock_edges),
    (is_gemfile, gemfile_edges),
    (is_gemfile_lock, gemfile_lock_edges),
    (is_gleam_toml, gleam_edges),
    (is_nuget_lock, nuget_lock_edges),
    (is_swift_resolved, swift_resolved_edges),
    (is_gradle_lock, gradle_lock_edges),
    (is_pubspec_yaml, pubspec_edges),
    (is_pubspec_lock, pubspec_lock_edges),
    (is_conda_environment_path, conda_environment_edges),
    (is_pipfile, pipfile_edges),
    (is_requirements_path, requirements_edges),
    (is_pyproject_toml, pyproject_edges),
    (is_r_description, r_description_edges),
    (is_renv_lock, renv_lock_edges),
    (is_podfile_lock, podfile_lock_edges),
    (is_helm_lock, helm_lock_edges),
    (is_helm_chart, helm_chart_edges),
    (is_cartfile_resolved, cartfile_resolved_edges),
    (is_elm_json, elm_edges),
    (is_julia_project, julia_project_edges),
    (is_conanfile_txt, conanfile_edges),
    (is_vcpkg_json, vcpkg_edges),
    (is_cpanfile, cpanfile_edges),
    (is_opam_file, opam_edges),
    (is_cabal_file, cabal_edges),
    (is_shard_yml, shard_edges),
    (is_haxelib_json, haxelib_edges),
    (is_nimble_file, nimble_edges),
    (is_deno_json, deno_edges),
    (is_deno_lock, deno_lock_edges),
    (is_maven_pom, maven_pom_edges),
    (is_mix_exs, mix_edges),
    (is_mix_lock, mix_lock_edges),
    (is_sbt_build, sbt_edges),
    (is_dotnet_project, dotnet_project_edges),
];

fn is_requirements_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(is_requirements_manifest)
}

pub(super) fn dependency_edges_for_path(
    target: &Path,
    path: &Path,
) -> Result<Vec<SbomDependencyEdge>> {
    for (matches, read) in EDGE_READERS {
        if matches(path) {
            return read(target, path);
        }
    }
    Ok(Vec::new())
}
