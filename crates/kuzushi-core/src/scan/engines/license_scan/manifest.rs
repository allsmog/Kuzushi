use anyhow::{Context, Result};
use roxmltree::Node;
use serde_json::Value;
use std::path::Path;

pub(super) enum ManifestLicense {
    Skip,
    Missing,
    Declared(String),
}

pub(super) fn is_license_manifest(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            matches!(
                name,
                "package.json"
                    | "composer.json"
                    | "Cargo.toml"
                    | "pyproject.toml"
                    | "pom.xml"
                    | "pubspec.yaml"
                    | "haxelib.json"
                    | "gleam.toml"
                    | "shard.yml"
                    | "shard.yaml"
                    | "bower.json"
                    | "elm.json"
                    | "vcpkg.json"
                    | "DESCRIPTION"
            )
        })
        || is_opam_file(path)
        || is_nimble_file(path)
        || is_cabal_file(path)
        || is_dotnet_project(path)
}

pub(super) fn manifest_license(path: &Path, text: &str) -> Result<ManifestLicense> {
    match path.file_name().and_then(|name| name.to_str()) {
        Some("package.json") => json_manifest_license(text, "package.json", true),
        Some("composer.json") => json_manifest_license(text, "composer.json", false),
        Some("Cargo.toml") => toml_license(text, &["package", "license"]),
        Some("pyproject.toml") => toml_license(text, &["project", "license"]),
        Some("pom.xml") => maven_pom_license(text),
        Some("pubspec.yaml") => pubspec_yaml_license(text),
        Some("haxelib.json") => json_manifest_license(text, "haxelib.json", false),
        Some("gleam.toml") => gleam_toml_license(text),
        Some("shard.yml") | Some("shard.yaml") => shard_yaml_license(text),
        Some("bower.json") => json_manifest_license(text, "bower.json", false),
        Some("elm.json") => json_manifest_license(text, "elm.json", false),
        Some("vcpkg.json") => json_manifest_license(text, "vcpkg.json", false),
        Some("DESCRIPTION") => r_description_license(text),
        _ if is_opam_file(path) => opam_license(text),
        _ if is_nimble_file(path) => nimble_license(text),
        _ if is_cabal_file(path) => cabal_license(text),
        _ if is_dotnet_project(path) => dotnet_project_license(text),
        _ => Ok(ManifestLicense::Skip),
    }
}

fn json_manifest_license(
    text: &str,
    manifest_name: &str,
    skip_private_packages: bool,
) -> Result<ManifestLicense> {
    let value: Value = serde_json::from_str(text)
        .with_context(|| format!("license-scan: parse {manifest_name}"))?;
    if skip_private_packages && value.get("private").and_then(Value::as_bool) == Some(true) {
        return Ok(ManifestLicense::Skip);
    }
    Ok(license_value(json_license(value.get("license"))))
}

fn json_license(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::String(text) => nonempty_license(text),
        Value::Array(values) => values
            .iter()
            .find_map(|value| value.as_str().and_then(nonempty_license)),
        Value::Object(fields) => fields
            .get("type")
            .and_then(Value::as_str)
            .and_then(nonempty_license),
        _ => None,
    }
}

fn toml_license(text: &str, path: &[&str]) -> Result<ManifestLicense> {
    let value: toml::Value = toml::from_str(text).context("license-scan: parse TOML manifest")?;
    Ok(license_value(
        path.iter()
            .try_fold(&value, |current, key| current.get(*key))
            .and_then(toml_license_value),
    ))
}

fn toml_license_value(value: &toml::Value) -> Option<String> {
    value
        .as_str()
        .and_then(nonempty_license)
        .or_else(|| table_license_text(value))
        .or_else(|| table_license_file(value))
}

fn table_license_text(value: &toml::Value) -> Option<String> {
    value
        .get("text")
        .and_then(toml::Value::as_str)
        .and_then(nonempty_license)
}

fn table_license_file(value: &toml::Value) -> Option<String> {
    value
        .get("file")
        .and_then(toml::Value::as_str)
        .and_then(nonempty_license)
        .map(|file| format!("file:{file}"))
}

fn gleam_toml_license(text: &str) -> Result<ManifestLicense> {
    let value: toml::Value = toml::from_str(text).context("license-scan: parse gleam.toml")?;
    Ok(license_value(
        value
            .get("licences")
            .and_then(toml_license_array_value)
            .or_else(|| value.get("licenses").and_then(toml_license_array_value)),
    ))
}

fn toml_license_array_value(value: &toml::Value) -> Option<String> {
    value
        .as_array()
        .and_then(|licenses| licenses.iter().find_map(toml_license_value))
}

fn dotnet_project_license(text: &str) -> Result<ManifestLicense> {
    let document =
        roxmltree::Document::parse(text).context("license-scan: parse .NET project file")?;
    let project = document.root_element();
    if child_text(project, "PackageLicenseFile").is_some() {
        return Ok(ManifestLicense::Skip);
    }
    if is_dotnet_package_project(project) {
        return Ok(license_value(
            child_text(project, "PackageLicenseExpression").map(str::to_string),
        ));
    }
    Ok(ManifestLicense::Skip)
}

fn maven_pom_license(text: &str) -> Result<ManifestLicense> {
    let document = roxmltree::Document::parse(text).context("license-scan: parse Maven pom.xml")?;
    let license = license_elements(document.root_element())
        .find_map(|license| child_text(license, "name"))
        .map(str::to_string);
    Ok(license_value(license))
}

fn pubspec_yaml_license(text: &str) -> Result<ManifestLicense> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).context("license-scan: parse pubspec.yaml")?;
    Ok(yaml_license_value(&value))
}

fn shard_yaml_license(text: &str) -> Result<ManifestLicense> {
    let value: serde_yaml::Value =
        serde_yaml::from_str(text).context("license-scan: parse shard.yml")?;
    Ok(yaml_license_value(&value))
}

fn yaml_license_value(value: &serde_yaml::Value) -> ManifestLicense {
    license_value(
        value
            .get("license")
            .and_then(serde_yaml::Value::as_str)
            .and_then(nonempty_license),
    )
}

fn nimble_license(text: &str) -> Result<ManifestLicense> {
    Ok(license_value(text.lines().find_map(|line| {
        quoted_line_license(line, "license", '=')
    })))
}

fn opam_license(text: &str) -> Result<ManifestLicense> {
    Ok(license_value(text.lines().find_map(|line| {
        quoted_line_license(line, "license", ':')
    })))
}

fn cabal_license(text: &str) -> Result<ManifestLicense> {
    Ok(license_value(
        text.lines()
            .find_map(|line| colon_line_license(line, "license")),
    ))
}

fn r_description_license(text: &str) -> Result<ManifestLicense> {
    Ok(license_value(
        text.lines()
            .find_map(|line| colon_line_license(line, "License")),
    ))
}

fn quoted_line_license(line: &str, key: &str, separator: char) -> Option<String> {
    let line = line.split('#').next().unwrap_or(line).trim();
    let value = line.strip_prefix(key)?.trim();
    let value = value.strip_prefix(separator)?.trim();
    quoted_assignment_value(value).and_then(nonempty_license)
}

fn colon_line_license(line: &str, key: &str) -> Option<String> {
    let line = line.split("--").next().unwrap_or(line).trim();
    let value = line.strip_prefix(key)?.trim();
    let value = value.strip_prefix(':')?.trim();
    nonempty_license(value)
}

fn quoted_assignment_value(value: &str) -> Option<&str> {
    let quote = value.as_bytes().first().copied()?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let end = value[1..].find(char::from(quote))?;
    Some(&value[1..end + 1])
}

fn license_elements<'a>(root: Node<'a, 'a>) -> impl Iterator<Item = Node<'a, 'a>> {
    root.children()
        .filter(|child| child.is_element() && child.tag_name().name() == "licenses")
        .flat_map(|licenses| {
            licenses
                .children()
                .filter(|child| child.is_element() && child.tag_name().name() == "license")
        })
}

fn is_dotnet_project(path: &Path) -> bool {
    path_extension(path)
        .is_some_and(|extension| matches!(extension.as_str(), "csproj" | "fsproj" | "vbproj"))
}

fn is_nimble_file(path: &Path) -> bool {
    path_extension(path).is_some_and(|extension| extension == "nimble")
}

fn is_opam_file(path: &Path) -> bool {
    path_extension(path).is_some_and(|extension| extension == "opam")
}

fn is_cabal_file(path: &Path) -> bool {
    path_extension(path).is_some_and(|extension| extension == "cabal")
}

fn path_extension(path: &Path) -> Option<String> {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| extension.to_ascii_lowercase())
}

fn is_dotnet_package_project(project: Node<'_, '_>) -> bool {
    child_text(project, "PackageId").is_some()
        || child_text(project, "PackageLicenseExpression").is_some()
        || child_text(project, "GeneratePackageOnBuild").is_some_and(is_truthy_xml_text)
}

fn child_text<'a>(node: Node<'a, 'a>, name: &'static str) -> Option<&'a str> {
    node.descendants()
        .filter(|child| child.is_element() && child.tag_name().name() == name)
        .find_map(|child| child.text())
        .map(str::trim)
        .filter(|text| !text.is_empty())
}

fn is_truthy_xml_text(value: &str) -> bool {
    value.eq_ignore_ascii_case("true")
}

fn nonempty_license(value: &str) -> Option<String> {
    let license = value.trim();
    if license.is_empty() {
        None
    } else {
        Some(license.to_string())
    }
}

fn license_value(value: Option<String>) -> ManifestLicense {
    value.map_or(ManifestLicense::Missing, ManifestLicense::Declared)
}
