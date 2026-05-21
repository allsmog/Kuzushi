use super::*;

pub(crate) fn analyze_deno_import_manifest(
    file_path: &Path,
    raw: &str,
    manifest: ManifestKind,
) -> Vec<DepHygieneFinding> {
    let Ok(parsed) = serde_json::from_str::<Value>(raw) else {
        return Vec::new();
    };

    let mut out = Vec::new();
    analyze_import_scope(file_path, manifest, "imports", parsed.get("imports"), &mut out);
    analyze_scoped_imports(file_path, manifest, &parsed, &mut out);
    out
}

fn analyze_scoped_imports(
    file_path: &Path,
    manifest: ManifestKind,
    parsed: &Value,
    out: &mut Vec<DepHygieneFinding>,
) {
    let Some(scopes) = parsed.get("scopes").and_then(Value::as_object) else {
        return;
    };
    for (scope, imports) in scopes {
        analyze_import_scope(
            file_path,
            manifest,
            &format!("scopes.{scope}"),
            Some(imports),
            out,
        );
    }
}

fn analyze_import_scope(
    file_path: &Path,
    manifest: ManifestKind,
    section: &str,
    value: Option<&Value>,
    out: &mut Vec<DepHygieneFinding>,
) {
    let Some(imports) = value.and_then(Value::as_object) else {
        return;
    };
    for specifier in imports.values().filter_map(Value::as_str) {
        if let Some(dependency) = deno_dependency(specifier) {
            push_deno_finding(file_path, manifest, section, &dependency, out);
        }
    }
}

fn push_deno_finding(
    file_path: &Path,
    manifest: ManifestKind,
    section: &str,
    dependency: &DenoDependency,
    out: &mut Vec<DepHygieneFinding>,
) {
    let Some((severity, reason)) = deno_version_risk(dependency.version.as_deref()) else {
        return;
    };
    out.push(DepHygieneFinding::new(
        manifest,
        file_path,
        &dependency.name,
        &dependency.specifier,
        severity,
        format!("{section}: {reason}"),
    ));
}

fn deno_version_risk(version: Option<&str>) -> Option<(DepHygieneSeverity, &'static str)> {
    let Some(version) = version.map(str::trim).filter(|version| !version.is_empty()) else {
        return Some((
            DepHygieneSeverity::High,
            "unversioned Deno npm/JSR import; pin an immutable package version",
        ));
    };
    if is_floating_deno_version(version) {
        return Some((
            DepHygieneSeverity::High,
            "floating Deno npm/JSR import tag; pin an immutable package version",
        ));
    }
    if is_floor_only_number_range(version) {
        return Some((
            DepHygieneSeverity::Medium,
            "floor-only Deno npm/JSR import range; declare an upper bound",
        ));
    }
    None
}

fn is_floating_deno_version(version: &str) -> bool {
    version == "*" || version.eq_ignore_ascii_case("latest")
}

fn deno_dependency(value: &str) -> Option<DenoDependency> {
    let specifier = value
        .strip_prefix("npm:")
        .or_else(|| value.strip_prefix("jsr:"))?;
    let (name, version) = package_specifier(specifier)?;
    Some(DenoDependency {
        name,
        version,
        specifier: value.to_string(),
    })
}

fn package_specifier(specifier: &str) -> Option<(String, Option<String>)> {
    if specifier.starts_with('@') {
        return scoped_package_specifier(specifier);
    }
    let package = specifier.split('/').next()?.trim();
    split_version(package)
}

fn scoped_package_specifier(specifier: &str) -> Option<(String, Option<String>)> {
    let mut segments = specifier.split('/');
    let scope = segments.next()?.trim();
    let package = segments.next()?.trim();
    let (package, version) = split_version(package)?;
    Some((format!("{scope}/{package}"), version))
}

fn split_version(value: &str) -> Option<(String, Option<String>)> {
    if value.is_empty() {
        return None;
    }
    let (name, version) = value
        .rsplit_once('@')
        .filter(|(name, version)| !name.is_empty() && !version.is_empty())
        .map_or((value, None), |(name, version)| (name, Some(version)));
    Some((name.to_string(), version.map(str::to_string)))
}

struct DenoDependency {
    name: String,
    version: Option<String>,
    specifier: String,
}
