use super::*;

pub(crate) fn textual_cvss_severity(value: &str) -> Severity {
    let upper = value.to_ascii_uppercase();
    if upper.contains("CRITICAL") {
        Severity::Critical
    // CVSS v3 vector form encodes impact metrics as /C:H/I:H/A:H. Any
    // high-impact letter on confidentiality, integrity, or availability is
    // a High signal — close enough for triage without a full CVSS parser.
    } else if contains_any(&upper, &["HIGH", "C:H", "I:H", "A:H"]) {
        Severity::High
    } else if upper.contains("MEDIUM") {
        Severity::Medium
    } else if contains_any(&upper, &["LOW", "C:L", "I:L", "A:L"]) {
        Severity::Low
    } else {
        Severity::Medium
    }
}

pub(crate) fn contains_any(value: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| value.contains(needle))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    PackageJson,
    PyprojectToml,
    RequirementsTxt,
    Pipfile,
    ComposerJson,
    DotnetProject,
    MavenPom,
    GradleBuild,
    Gemfile,
    BowerJson,
    ConanfileTxt,
    PubspecYaml,
    HaxelibJson,
    Cpanfile,
    RDescription,
    CondaEnvironmentYml,
    CondaEnvironmentYaml,
    GleamToml,
    ShardYml,
    ShardYaml,
    OpamFile,
    NimbleFile,
    CabalFile,
    ElmJson,
    MixExs,
    SbtBuild,
    JuliaProjectToml,
    DenoJson,
    ImportMapJson,
    CargoToml,
    GoMod,
}

impl ManifestKind {
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            Self::PackageJson => "package.json",
            Self::PyprojectToml => "pyproject.toml",
            Self::RequirementsTxt => "requirements.txt",
            Self::Pipfile => "Pipfile",
            Self::ComposerJson => "composer.json",
            Self::DotnetProject => "dotnet-project",
            Self::MavenPom => "pom.xml",
            Self::GradleBuild => "gradle-build",
            Self::Gemfile => "Gemfile",
            Self::BowerJson => "bower.json",
            Self::ConanfileTxt => "conanfile.txt",
            Self::PubspecYaml => "pubspec.yaml",
            Self::HaxelibJson => "haxelib.json",
            Self::Cpanfile => "cpanfile",
            Self::RDescription => "DESCRIPTION",
            Self::CondaEnvironmentYml => "environment.yml",
            Self::CondaEnvironmentYaml => "environment.yaml",
            Self::GleamToml => "gleam.toml",
            Self::ShardYml => "shard.yml",
            Self::ShardYaml => "shard.yaml",
            Self::OpamFile => "opam",
            Self::NimbleFile => "nimble",
            Self::CabalFile => "cabal",
            Self::ElmJson => "elm.json",
            Self::MixExs => "mix.exs",
            Self::SbtBuild => "build.sbt",
            Self::JuliaProjectToml => "Project.toml",
            Self::DenoJson => "deno.json",
            Self::ImportMapJson => "import_map.json",
            Self::CargoToml => "Cargo.toml",
            Self::GoMod => "go.mod",
        }
    }
}

pub(crate) const TARGET_MANIFESTS: [ManifestKind; 26] = [
    ManifestKind::PackageJson,
    ManifestKind::PyprojectToml,
    ManifestKind::RequirementsTxt,
    ManifestKind::Pipfile,
    ManifestKind::ComposerJson,
    ManifestKind::MavenPom,
    ManifestKind::Gemfile,
    ManifestKind::BowerJson,
    ManifestKind::ConanfileTxt,
    ManifestKind::PubspecYaml,
    ManifestKind::HaxelibJson,
    ManifestKind::Cpanfile,
    ManifestKind::RDescription,
    ManifestKind::CondaEnvironmentYml,
    ManifestKind::CondaEnvironmentYaml,
    ManifestKind::GleamToml,
    ManifestKind::ShardYml,
    ManifestKind::ShardYaml,
    ManifestKind::ElmJson,
    ManifestKind::MixExs,
    ManifestKind::SbtBuild,
    ManifestKind::JuliaProjectToml,
    ManifestKind::DenoJson,
    ManifestKind::ImportMapJson,
    ManifestKind::CargoToml,
    ManifestKind::GoMod,
];

pub fn check_dependency_hygiene(target: &Path) -> Result<DepHygieneReport> {
    let inspection = inspect_dependency_hygiene(target, &ScanCancellation::default())?;
    inspection.ensure_complete()?;
    Ok(inspection.report)
}

pub fn analyze_manifest(
    manifest: ManifestKind,
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    match manifest {
        ManifestKind::PackageJson => analyze_package_json(file_path, raw),
        ManifestKind::PyprojectToml => analyze_pyproject_toml(file_path, raw),
        ManifestKind::RequirementsTxt => analyze_requirements_txt(file_path, raw),
        ManifestKind::Pipfile => analyze_pipfile(file_path, raw),
        ManifestKind::ComposerJson => analyze_composer_json(file_path, raw),
        ManifestKind::DotnetProject => analyze_dotnet_project(file_path, raw),
        ManifestKind::MavenPom => analyze_maven_pom(file_path, raw),
        ManifestKind::GradleBuild => analyze_gradle_build(file_path, raw),
        ManifestKind::Gemfile => analyze_gemfile(file_path, raw),
        ManifestKind::BowerJson => analyze_bower_json(file_path, raw),
        ManifestKind::ConanfileTxt => analyze_conanfile_txt(file_path, raw),
        ManifestKind::PubspecYaml => analyze_pubspec_yaml(file_path, raw),
        ManifestKind::HaxelibJson => analyze_haxelib_json(file_path, raw),
        ManifestKind::Cpanfile => analyze_cpanfile(file_path, raw),
        ManifestKind::RDescription => analyze_r_description(file_path, raw),
        extended => analyze_extended_manifest(extended, file_path, raw),
    }
}

fn analyze_extended_manifest(
    manifest: ManifestKind,
    file_path: &Path,
    raw: &str,
) -> Vec<DepHygieneFinding> {
    match manifest {
        ManifestKind::CondaEnvironmentYml | ManifestKind::CondaEnvironmentYaml => {
            analyze_conda_environment(file_path, raw, manifest)
        }
        ManifestKind::GleamToml => analyze_gleam_toml(file_path, raw),
        ManifestKind::ShardYml | ManifestKind::ShardYaml => {
            analyze_shard_manifest(file_path, raw, manifest)
        }
        ManifestKind::OpamFile => analyze_opam_file(file_path, raw),
        ManifestKind::NimbleFile => analyze_nimble_file(file_path, raw),
        ManifestKind::CabalFile => analyze_cabal_file(file_path, raw),
        ManifestKind::ElmJson => analyze_elm_json(file_path, raw),
        ManifestKind::MixExs => analyze_mix_exs(file_path, raw),
        ManifestKind::SbtBuild => analyze_sbt_build(file_path, raw),
        ManifestKind::JuliaProjectToml => analyze_julia_project_toml(file_path, raw),
        ManifestKind::DenoJson | ManifestKind::ImportMapJson => {
            analyze_deno_import_manifest(file_path, raw, manifest)
        }
        ManifestKind::CargoToml => analyze_cargo_toml(file_path, raw),
        ManifestKind::GoMod => analyze_go_mod(file_path, raw),
        _ => unreachable!("core manifest routed to extended analyzer"),
    }
}
