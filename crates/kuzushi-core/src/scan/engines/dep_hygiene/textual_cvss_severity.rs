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
    let target = canonical_directory(target)?;
    let mut findings = Vec::new();

    for manifest in TARGET_MANIFESTS {
        let manifest_path = target.join(manifest.file_name());
        if !manifest_path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&manifest_path)
            .with_context(|| format!("dep-hygiene: failed to read {}", manifest_path.display()))?;
        findings.extend(analyze_manifest(manifest, &manifest_path, &raw));
    }
    findings.extend(check_dotnet_projects(&target)?);
    findings.extend(check_gradle_builds(&target)?);
    findings.extend(check_extension_files(&target, "opam", analyze_opam_file)?);
    findings.extend(check_extension_files(&target, "nimble", analyze_nimble_file)?);
    findings.extend(check_extension_files(&target, "cabal", analyze_cabal_file)?);

    Ok(DepHygieneReport {
        target: target.display().to_string(),
        count: findings.len(),
        findings,
    })
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
        ManifestKind::CondaEnvironmentYml | ManifestKind::CondaEnvironmentYaml => {
            analyze_conda_environment(file_path, raw, manifest)
        }
        ManifestKind::GleamToml => analyze_gleam_toml(file_path, raw),
        ManifestKind::ShardYml | ManifestKind::ShardYaml => analyze_shard_manifest(file_path, raw, manifest),
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
    }
}

fn check_dotnet_projects(target: &Path) -> Result<Vec<DepHygieneFinding>> {
    let mut findings = Vec::new();
    for entry in
        fs::read_dir(target).with_context(|| format!("dep-hygiene: failed to read {}", target.display()))?
    {
        let path = entry?.path();
        if !is_dotnet_project(&path) {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("dep-hygiene: failed to read {}", path.display()))?;
        findings.extend(analyze_dotnet_project(&path, &raw));
    }
    Ok(findings)
}

fn is_dotnet_project(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            matches!(
                extension.to_ascii_lowercase().as_str(),
                "csproj" | "fsproj" | "vbproj"
            )
        })
}

fn check_gradle_builds(target: &Path) -> Result<Vec<DepHygieneFinding>> {
    let mut findings = Vec::new();
    for name in ["build.gradle", "build.gradle.kts"] {
        let path = target.join(name);
        if !path.exists() {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("dep-hygiene: failed to read {}", path.display()))?;
        findings.extend(analyze_gradle_build(&path, &raw));
    }
    Ok(findings)
}

fn check_extension_files(
    target: &Path,
    extension: &str,
    analyze: fn(&Path, &str) -> Vec<DepHygieneFinding>,
) -> Result<Vec<DepHygieneFinding>> {
    let mut findings = Vec::new();
    for entry in
        fs::read_dir(target).with_context(|| format!("dep-hygiene: failed to read {}", target.display()))?
    {
        let path = entry?.path();
        if !has_extension(&path, extension) {
            continue;
        }
        let raw = fs::read_to_string(&path)
            .with_context(|| format!("dep-hygiene: failed to read {}", path.display()))?;
        findings.extend(analyze(&path, &raw));
    }
    Ok(findings)
}

fn has_extension(path: &Path, expected: &str) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension == expected)
}
