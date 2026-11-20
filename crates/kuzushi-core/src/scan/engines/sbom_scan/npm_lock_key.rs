use serde_json::Value;

/// The name the dependency graph gives the scanned project itself, which the
/// `packages` map keys with the empty string.
pub(super) const ROOT_PACKAGE: &str = "root";

const INSTALL_TREE: &str = "node_modules/";
const ALIAS_SPEC: &str = "npm:";

/// The package an npm lockfile v2/v3 `packages` entry describes, or `None` for
/// the root entry, which names the scanned project rather than a dependency.
///
/// The key is the directory the package was installed into, not its name, so
/// three readings differ from a plain split of the key and npm records in the
/// entry which one applies:
///
/// * a nested install (`node_modules/a/node_modules/@babel/core`) is named
///   after its own `node_modules/` segment — neither the first path segment
///   nor the last;
/// * an alias (`node_modules/alias`) and a workspace link (`packages/app`)
///   carry the installed package's real name in `name`, the only place it
///   appears;
/// * a workspace directory with no declared `name` is named by its own last
///   segment.
pub(super) fn package_name(key: &str, entry: &Value) -> Option<String> {
    let trimmed = key.trim_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    let name = declared_name(entry).unwrap_or_else(|| installed_name(trimmed));
    Some(name.to_string())
}

/// The name npm wrote into the entry, which it does exactly when the key does
/// not spell the name.
fn declared_name(entry: &Value) -> Option<&str> {
    entry
        .get("name")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|name| !name.is_empty())
}

/// The name a key spells. An npm package name is either `name` or
/// `@scope/name`, so everything after the last install-tree segment is the
/// whole name and needs no further splitting; a key outside an install tree is
/// a workspace directory, named by its last segment.
fn installed_name(trimmed: &str) -> &str {
    match trimmed.rsplit_once(INSTALL_TREE) {
        Some((_, name)) => name,
        None => trimmed.rsplit('/').next().unwrap_or(trimmed),
    }
}

/// The package a dependency entry names. A spec of `npm:<name>@<range>`
/// installs `<name>` under the declared key, so there the key is a directory
/// name and only the spec holds the package — the same split as a `packages`
/// key and its `"name"`. Any other spec is a version range for the package the
/// key names.
pub(super) fn dependency_target(key: &str, spec: &Value) -> String {
    spec.as_str()
        .and_then(|spec| spec.trim().strip_prefix(ALIAS_SPEC))
        .and_then(aliased_package_name)
        .unwrap_or_else(|| key.to_string())
}

/// `lodash` from `npm:lodash@4.17.21` and `@scope/pkg` from
/// `npm:@scope/pkg@1.0.0`. The version separator is the last `@`; a scope's
/// leading `@` is not one, and an alias may carry no version at all.
fn aliased_package_name(spec: &str) -> Option<String> {
    let name = match spec.rfind('@') {
        Some(0) | None => spec,
        Some(at) => &spec[..at],
    };
    (!name.is_empty()).then(|| name.to_string())
}
