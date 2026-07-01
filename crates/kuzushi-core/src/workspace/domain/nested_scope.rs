use super::*;
use std::collections::BTreeMap;
use std::path::Component;

pub const PROJECT_MODEL_DIR: &str = "project-model";
pub const PROJECT_MODEL_SCOPES_FILE: &str = "scopes.json";
pub const ROOT_SCOPE_ID: &str = "root";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NestedProjectScopeTree {
    #[serde(default = "default_scope_schema_version")]
    pub schema_version: u32,
    pub root: String,
    pub scopes: Vec<NestedProjectScope>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct NestedProjectScope {
    pub id: String,
    pub parent: Option<String>,
    pub kind: NestedProjectKind,
    pub rel_path: String,
    pub inherited_sections: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum NestedProjectKind {
    Root,
    Submodule,
    VendoredRoot,
    DependencyRoot,
}

impl NestedProjectScopeTree {
    pub fn root_scope(&self) -> Option<&NestedProjectScope> {
        self.scopes.iter().find(|scope| scope.id == self.root)
    }

    pub fn non_root_scopes(&self) -> impl Iterator<Item = &NestedProjectScope> {
        self.scopes.iter().filter(|scope| scope.kind != NestedProjectKind::Root)
    }
}

impl NestedProjectScope {
    pub fn absolute_path(&self, root: impl AsRef<Path>) -> PathBuf {
        if self.rel_path == "." {
            root.as_ref().to_path_buf()
        } else {
            root.as_ref().join(&self.rel_path)
        }
    }

    pub fn display_label(&self) -> String {
        if self.rel_path == "." {
            ".".to_string()
        } else {
            self.rel_path.clone()
        }
    }
}

impl NestedProjectKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Submodule => "submodule",
            Self::VendoredRoot => "vendored",
            Self::DependencyRoot => "dependency",
        }
    }

    fn id_prefix(self) -> &'static str {
        match self {
            Self::Root => ROOT_SCOPE_ID,
            Self::Submodule => "submodule",
            Self::VendoredRoot => "vendored",
            Self::DependencyRoot => "dependency",
        }
    }
}

pub fn project_model_dir(root: impl AsRef<Path>) -> PathBuf {
    workspace_state_dir(root).join(PROJECT_MODEL_DIR)
}

pub fn project_model_scopes_path(root: impl AsRef<Path>) -> PathBuf {
    project_model_dir(root).join(PROJECT_MODEL_SCOPES_FILE)
}

pub fn discover_nested_project_scopes(root: impl AsRef<Path>) -> NestedProjectScopeTree {
    let root = root.as_ref();
    let mut scopes = BTreeMap::new();
    let root_scope = NestedProjectScope {
        id: ROOT_SCOPE_ID.to_string(),
        parent: None,
        kind: NestedProjectKind::Root,
        rel_path: ".".to_string(),
        inherited_sections: Vec::new(),
    };
    scopes.insert(root_scope.id.clone(), root_scope);
    for rel_path in discover_gitmodule_paths(root) {
        insert_scope(&mut scopes, root, NestedProjectKind::Submodule, rel_path);
    }
    for (kind, rel_path) in discover_dependency_roots(root) {
        insert_scope(&mut scopes, root, kind, rel_path);
    }
    let mut ordered_scopes = scopes.into_values().collect::<Vec<_>>();
    ordered_scopes.sort_by(|left, right| {
        scope_sort_key(left)
            .cmp(&scope_sort_key(right))
            .then_with(|| left.rel_path.cmp(&right.rel_path))
    });
    NestedProjectScopeTree {
        schema_version: default_scope_schema_version(),
        root: ROOT_SCOPE_ID.to_string(),
        scopes: ordered_scopes,
    }
}

pub fn load_nested_project_scopes(root: impl AsRef<Path>) -> Result<Option<NestedProjectScopeTree>> {
    let path = project_model_scopes_path(root);
    if !path.exists() {
        return Ok(None);
    }
    let body =
        fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let tree = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(Some(tree))
}

pub fn save_nested_project_scopes(
    root: impl AsRef<Path>,
    tree: &NestedProjectScopeTree,
) -> Result<PathBuf> {
    let path = project_model_scopes_path(root);
    let Some(parent) = path.parent() else {
        anyhow::bail!("scope tree path has no parent: {}", path.display());
    };
    fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;
    let body = serde_json::to_string_pretty(tree).context("Could not serialize scope tree")?;
    fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn discover_and_save_nested_project_scopes(
    root: impl AsRef<Path>,
) -> Result<NestedProjectScopeTree> {
    let root = root.as_ref();
    let tree = discover_nested_project_scopes(root);
    save_nested_project_scopes(root, &tree)?;
    Ok(tree)
}

fn insert_scope(
    scopes: &mut BTreeMap<String, NestedProjectScope>,
    root: &Path,
    kind: NestedProjectKind,
    rel_path: String,
) {
    if !root.join(&rel_path).is_dir() {
        return;
    }
    let id = scope_id(kind, &rel_path);
    scopes.entry(id.clone()).or_insert_with(|| NestedProjectScope {
        id,
        parent: Some(ROOT_SCOPE_ID.to_string()),
        kind,
        rel_path,
        inherited_sections: inherited_sections_for_child_scope(),
    });
}

fn discover_gitmodule_paths(root: &Path) -> Vec<String> {
    let Ok(body) = fs::read_to_string(root.join(".gitmodules")) else {
        return Vec::new();
    };
    body.lines()
        .filter_map(gitmodule_path_line)
        .filter_map(|line| normalize_relative_path(&line))
        .collect()
}

fn gitmodule_path_line(line: &str) -> Option<String> {
    let (key, value) = line.trim().split_once('=')?;
    (key.trim() == "path")
        .then(|| trim_gitmodule_value(value))
        .filter(|value| !value.is_empty())
}

fn trim_gitmodule_value(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn discover_dependency_roots(root: &Path) -> Vec<(NestedProjectKind, String)> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut roots = entries
        .flatten()
        .filter_map(|entry| dependency_scope_for_entry(&entry.path()))
        .collect::<Vec<_>>();
    roots.sort();
    roots
}

fn dependency_scope_for_entry(path: &Path) -> Option<(NestedProjectKind, String)> {
    if !path.is_dir() {
        return None;
    }
    let name = path.file_name()?.to_string_lossy();
    let lower = name.to_ascii_lowercase();
    if !crate::workspace::inventory::vendor_dir(&lower) || lower == "__pycache__" {
        return None;
    }
    let kind = match lower.as_str() {
        "node_modules" | ".venv" | "venv" => NestedProjectKind::DependencyRoot,
        "vendor" | "third_party" | "third-party" | "external" => NestedProjectKind::VendoredRoot,
        _ => return None,
    };
    Some((kind, name.to_string()))
}

fn inherited_sections_for_child_scope() -> Vec<String> {
    vec!["context-feed".to_string(), "threat-model".to_string()]
}

fn scope_id(kind: NestedProjectKind, rel_path: &str) -> String {
    if kind == NestedProjectKind::Root {
        return ROOT_SCOPE_ID.to_string();
    }
    format!("{}-{}", kind.id_prefix(), slugify_scope_path(rel_path))
}

fn scope_sort_key(scope: &NestedProjectScope) -> (u8, NestedProjectKind) {
    let root_first = if scope.kind == NestedProjectKind::Root {
        0
    } else {
        1
    };
    (root_first, scope.kind)
}

fn slugify_scope_path(value: &str) -> String {
    let mut slug = String::new();
    let mut last_was_dash = false;
    for character in value.chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
            last_was_dash = false;
        } else if !last_was_dash {
            slug.push('-');
            last_was_dash = true;
        }
    }
    let slug = slug.trim_matches('-').to_string();
    if slug.is_empty() {
        "scope".to_string()
    } else {
        slug
    }
}

fn normalize_relative_path(value: &str) -> Option<String> {
    let normalized = value.trim().replace('\\', "/");
    if normalized.is_empty() {
        return None;
    }
    let path = Path::new(&normalized);
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => components.push(part.to_string_lossy().to_string()),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => return None,
        }
    }
    (!components.is_empty()).then(|| components.join("/"))
}

fn default_scope_schema_version() -> u32 {
    1
}

#[cfg(test)]
mod tests;
