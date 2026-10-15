use super::*;

pub(super) fn manifest_kind(path: &Path) -> Option<ManifestKind> {
    let name = path.file_name()?.to_str()?;
    TARGET_MANIFESTS
        .iter()
        .copied()
        .find(|kind| kind.file_name() == name)
        .or_else(|| special_manifest(path, name))
}

fn special_manifest(path: &Path, name: &str) -> Option<ManifestKind> {
    if ["build.gradle", "build.gradle.kts"].contains(&name) {
        return Some(ManifestKind::GradleBuild);
    }
    match path.extension()?.to_str()?.to_ascii_lowercase().as_str() {
        "csproj" | "fsproj" | "vbproj" => Some(ManifestKind::DotnetProject),
        "opam" => Some(ManifestKind::OpamFile),
        "nimble" => Some(ManifestKind::NimbleFile),
        "cabal" => Some(ManifestKind::CabalFile),
        _ => None,
    }
}

pub(super) fn validate_document(kind: ManifestKind, raw: &str) -> Result<()> {
    match format(kind) {
        "json" => validate_json(raw),
        "toml" => {
            toml::from_str::<toml::Value>(raw).context("invalid TOML document")?;
            Ok(())
        }
        "yaml" => {
            let value = crate::yaml::parse_value(raw).context("invalid YAML document")?;
            anyhow::ensure!(value.is_object(), "manifest requires a YAML mapping");
            Ok(())
        }
        "xml" => {
            roxmltree::Document::parse(raw).context("invalid XML document")?;
            Ok(())
        }
        _ => Ok(()),
    }
}

fn validate_json(raw: &str) -> Result<()> {
    let value: Value = serde_json::from_str(raw).context("invalid JSON document")?;
    anyhow::ensure!(value.is_object(), "manifest requires a JSON object");
    Ok(())
}

fn format(kind: ManifestKind) -> &'static str {
    match kind {
        ManifestKind::PackageJson
        | ManifestKind::ComposerJson
        | ManifestKind::BowerJson
        | ManifestKind::HaxelibJson
        | ManifestKind::ElmJson
        | ManifestKind::DenoJson
        | ManifestKind::ImportMapJson => "json",
        ManifestKind::PyprojectToml
        | ManifestKind::Pipfile
        | ManifestKind::GleamToml
        | ManifestKind::JuliaProjectToml
        | ManifestKind::CargoToml => "toml",
        ManifestKind::PubspecYaml
        | ManifestKind::CondaEnvironmentYml
        | ManifestKind::CondaEnvironmentYaml
        | ManifestKind::ShardYml
        | ManifestKind::ShardYaml => "yaml",
        ManifestKind::DotnetProject | ManifestKind::MavenPom => "xml",
        _ => "text",
    }
}
