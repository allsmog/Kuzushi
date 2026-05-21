use super::*;
use super::edge_readers::dependency_edges_for_path;
use super::target::ignored_dir;
use serde_json::Value;

const NPM_LOCK_DEPENDENCY_FIELDS: &[&str] = &[
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
];

pub(super) fn collect_dependency_edges(
    target: &Path,
    cancellation: &ScanCancellation,
) -> Result<Vec<SbomDependencyEdge>> {
    let mut edges = Vec::new();
    collect_package_lock_edges(target, target, &mut edges, cancellation)?;
    edges.sort_by_key(edge_sort_key);
    edges.dedup();
    Ok(edges)
}

fn collect_package_lock_edges(
    target: &Path,
    dir: &Path,
    edges: &mut Vec<SbomDependencyEdge>,
    cancellation: &ScanCancellation,
) -> Result<()> {
    if cancellation.is_cancelled() {
        anyhow::bail!("sbom-scan scan cancelled");
    }
    for entry in fs::read_dir(dir).with_context(|| format!("sbom-scan: read {}", dir.display()))? {
        let path = entry?.path();
        if path.is_dir() && !ignored_dir(&path) {
            collect_package_lock_edges(target, &path, edges, cancellation)?;
        } else {
            edges.extend(dependency_edges_for_path(target, &path)?);
        }
    }
    Ok(())
}

pub(super) fn is_package_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| matches!(name, "package-lock.json" | "npm-shrinkwrap.json"))
}

pub(super) fn is_cargo_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "Cargo.lock")
}

pub(super) fn is_go_sum(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "go.sum")
}

pub(super) fn is_pnpm_lock(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name == "pnpm-lock.yaml")
}

pub(super) fn package_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: Value = serde_json::from_str(&text).context("sbom-scan: parse package lock")?;
    let source = relative_display(target, path);
    let mut edges = package_lock_v2_edges(&value, &source);
    edges.extend(package_lock_v1_edges(&value, &source));
    Ok(edges)
}

fn package_lock_v2_edges(value: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    value
        .get("packages")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|packages| packages.iter())
        .flat_map(|(key, package)| package_dependencies(key, package, &source))
        .collect()
}

fn package_lock_v1_edges(value: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    value
        .get("dependencies")
        .and_then(Value::as_object)
        .map(|dependencies| nested_npm_dependency_edges("root", dependencies, source))
        .unwrap_or_default()
}

pub(super) fn cargo_lock_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("sbom-scan: parse Cargo.lock")?;
    let source = relative_display(target, path);
    Ok(value
        .get("package")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .flat_map(|package| cargo_package_edges(package, &source))
        .collect())
}

fn cargo_package_edges(package: &toml::Value, source: &str) -> Vec<SbomDependencyEdge> {
    let Some(from) = package.get("name").and_then(toml::Value::as_str) else {
        return Vec::new();
    };
    package
        .get("dependencies")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .filter_map(cargo_dependency_name)
        .map(|to| SbomDependencyEdge {
            from: from.to_string(),
            to,
            source: source.to_string(),
        })
        .collect()
}

fn cargo_dependency_name(raw: &str) -> Option<String> {
    raw.split_whitespace()
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

pub(super) fn go_sum_edges(target: &Path, path: &Path) -> Result<Vec<SbomDependencyEdge>> {
    let text =
        fs::read_to_string(path).with_context(|| format!("sbom-scan: read {}", path.display()))?;
    let source = relative_display(target, path);
    Ok(text
        .lines()
        .filter_map(go_sum_module_name)
        .map(|to| SbomDependencyEdge {
            from: "root".to_string(),
            to,
            source: source.clone(),
        })
        .collect())
}

fn go_sum_module_name(line: &str) -> Option<String> {
    let name = line.split_whitespace().next()?.trim();
    if name.is_empty() {
        return None;
    }
    Some(name.strip_suffix("/go.mod").unwrap_or(name).to_string())
}

fn package_dependencies(key: &str, package: &Value, source: &str) -> Vec<SbomDependencyEdge> {
    NPM_LOCK_DEPENDENCY_FIELDS
        .iter()
        .filter_map(|field| package.get(*field).and_then(Value::as_object))
        .flat_map(|deps| deps.keys())
        .map(|dependency| SbomDependencyEdge {
            from: package_name_from_lock_key(key),
            to: dependency.clone(),
            source: source.to_string(),
        })
        .collect()
}

fn nested_npm_dependency_edges(
    from: &str,
    dependencies: &serde_json::Map<String, Value>,
    source: &str,
) -> Vec<SbomDependencyEdge> {
    dependencies
        .iter()
        .flat_map(|(name, dependency)| nested_npm_dependency_edge(from, name, dependency, source))
        .collect()
}

fn nested_npm_dependency_edge(
    from: &str,
    name: &str,
    dependency: &Value,
    source: &str,
) -> Vec<SbomDependencyEdge> {
    let mut edges = vec![SbomDependencyEdge {
        from: from.to_string(),
        to: name.to_string(),
        source: source.to_string(),
    }];
    if let Some(children) = dependency.get("dependencies").and_then(Value::as_object) {
        edges.extend(nested_npm_dependency_edges(name, children, source));
    }
    edges
}

fn package_name_from_lock_key(key: &str) -> String {
    let trimmed = key.trim_matches('/');
    if trimmed.is_empty() {
        return "root".to_string();
    }
    let Some(name) = trimmed.strip_prefix("node_modules/") else {
        return trimmed.to_string();
    };
    if let Some(scoped) = name.strip_prefix('@') {
        return scoped_package_name(scoped);
    }
    name.rsplit('/').next().unwrap_or(name).to_string()
}

fn scoped_package_name(value: &str) -> String {
    let mut parts = value.split('/');
    match (parts.next(), parts.next()) {
        (Some(scope), Some(name)) => format!("@{scope}/{name}"),
        _ => format!("@{value}"),
    }
}

fn edge_sort_key(edge: &SbomDependencyEdge) -> (String, String, String) {
    (edge.source.clone(), edge.from.clone(), edge.to.clone())
}
