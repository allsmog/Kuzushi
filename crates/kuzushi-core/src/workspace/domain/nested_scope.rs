use super::workspace_state_dir;
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

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

pub(crate) fn inherited_sections_for_child_scope() -> Vec<String> {
    vec!["context-feed".to_string(), "threat-model".to_string()]
}

pub(crate) fn scope_id(kind: NestedProjectKind, rel_path: &str) -> String {
    if kind == NestedProjectKind::Root {
        return ROOT_SCOPE_ID.to_string();
    }
    format!("{}-{}", kind.id_prefix(), slugify_scope_path(rel_path))
}

pub(crate) fn scope_sort_key(scope: &NestedProjectScope) -> (u8, NestedProjectKind) {
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

pub(crate) fn normalize_relative_path(value: &str) -> Option<String> {
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
