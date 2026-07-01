use super::*;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

mod formatting;
use formatting::{
    default_project_model_schema_version, join_framework_names, join_language_names, relative_path,
    value_hash,
};

pub const PROJECT_MODEL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectModelDocument {
    #[serde(default = "default_project_model_schema_version")]
    pub schema_version: u32,
    pub scope_id: String,
    pub scope_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub built_at_revision: Option<String>,
    pub sections: Vec<ProjectModelSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ProjectModelSection {
    pub key: String,
    pub origin: ProjectModelSectionOrigin,
    pub summary: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub built_at_revision: Option<String>,
    #[serde(default)]
    pub stale: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectModelSectionOrigin {
    Inherited,
    Local,
    Missing,
}

pub fn project_model_scope_path(root: impl AsRef<Path>, scope_id: &str) -> PathBuf {
    project_model_dir(root).join(format!("{scope_id}.json"))
}

pub fn build_project_model_document(
    root: impl AsRef<Path>,
    scope_id: &str,
    current_revision: Option<String>,
) -> Result<ProjectModelDocument> {
    let root = root.as_ref();
    let tree = load_nested_project_scopes(root)?
        .unwrap_or_else(|| discover_nested_project_scopes(root));
    build_project_model_document_from_tree(root, &tree, scope_id, current_revision)
}

pub fn load_project_model_document(
    root: impl AsRef<Path>,
    scope_id: &str,
    current_revision: Option<&str>,
) -> Result<Option<ProjectModelDocument>> {
    let root = root.as_ref();
    let path = project_model_scope_path(root, scope_id);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(&path).with_context(|| format!("Could not read {}", path.display()))?;
    let document = serde_json::from_str(&body)
        .with_context(|| format!("Could not parse {}", path.display()))?;
    Ok(Some(refresh_project_model_staleness(
        root,
        document,
        current_revision,
    )))
}

pub fn save_project_model_document(
    root: impl AsRef<Path>,
    document: &ProjectModelDocument,
) -> Result<PathBuf> {
    let path = project_model_scope_path(root, &document.scope_id);
    let Some(parent) = path.parent() else {
        anyhow::bail!("project model path has no parent: {}", path.display());
    };
    fs::create_dir_all(parent).with_context(|| format!("Could not create {}", parent.display()))?;
    let body = serde_json::to_string_pretty(document).context("Could not serialize project model")?;
    fs::write(&path, body).with_context(|| format!("Could not write {}", path.display()))?;
    Ok(path)
}

pub fn refresh_project_model_staleness(
    root: impl AsRef<Path>,
    mut document: ProjectModelDocument,
    current_revision: Option<&str>,
) -> ProjectModelDocument {
    let root = root.as_ref();
    for section in &mut document.sections {
        section.stale = section_is_stale(root, section, current_revision);
    }
    document
}

fn build_project_model_document_from_tree(
    root: &Path,
    tree: &NestedProjectScopeTree,
    scope_id: &str,
    current_revision: Option<String>,
) -> Result<ProjectModelDocument> {
    let scope = tree
        .scopes
        .iter()
        .find(|scope| scope.id == scope_id)
        .with_context(|| format!("unknown project scope {scope_id:?}"))?;
    let scope_root = scope.absolute_path(root);
    let mut sections = inherited_sections(root, tree, scope, current_revision.clone())?;
    merge_local_sections(
        &mut sections,
        local_sections(root, &scope_root, current_revision.as_deref()),
    );
    Ok(ProjectModelDocument {
        schema_version: PROJECT_MODEL_SCHEMA_VERSION,
        scope_id: scope.id.clone(),
        scope_path: scope.rel_path.clone(),
        built_at_revision: current_revision,
        sections: sections.into_values().collect(),
    })
}

fn inherited_sections(
    root: &Path,
    tree: &NestedProjectScopeTree,
    scope: &NestedProjectScope,
    current_revision: Option<String>,
) -> Result<BTreeMap<String, ProjectModelSection>> {
    let Some(parent_id) = scope.parent.as_deref() else {
        return Ok(BTreeMap::new());
    };
    let parent = build_project_model_document_from_tree(root, tree, parent_id, current_revision)?;
    let inherited_keys = scope
        .inherited_sections
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    Ok(parent
        .sections
        .into_iter()
        .filter(|section| inherited_keys.contains(&section.key.as_str()))
        .map(|mut section| {
            section.origin = ProjectModelSectionOrigin::Inherited;
            (section.key.clone(), section)
        })
        .collect())
}

fn local_sections(
    root: &Path,
    scope_root: &Path,
    current_revision: Option<&str>,
) -> Vec<ProjectModelSection> {
    vec![
        source_file_section(
            "context-feed",
            root,
            &crate::context::context_snapshot_path(scope_root),
            "context snapshot",
            current_revision,
        ),
        inventory_section(scope_root, current_revision),
        source_file_section(
            "threat-model",
            root,
            &crate::capabilities::persistent_threat_model_path(scope_root),
            "persistent threat model",
            current_revision,
        ),
        attack_surface_section(scope_root, current_revision),
    ]
}

fn merge_local_sections(
    sections: &mut BTreeMap<String, ProjectModelSection>,
    local_sections: Vec<ProjectModelSection>,
) {
    for section in local_sections {
        if section.origin == ProjectModelSectionOrigin::Missing
            && sections.contains_key(&section.key)
        {
            continue;
        }
        sections.insert(section.key.clone(), section);
    }
}

fn source_file_section(
    key: &str,
    root: &Path,
    source_path: &Path,
    label: &str,
    current_revision: Option<&str>,
) -> ProjectModelSection {
    match fs::read_to_string(source_path) {
        Ok(body) => ProjectModelSection {
            key: key.to_string(),
            origin: ProjectModelSectionOrigin::Local,
            summary: format!("{label} present"),
            source_path: Some(relative_path(root, source_path)),
            content_hash: Some(crate::static_evidence::static_content_hash(&body)),
            built_at_revision: current_revision.map(str::to_string),
            stale: false,
        },
        Err(_) => missing_section(key, format!("{label} missing"), current_revision),
    }
}

fn inventory_section(scope_root: &Path, current_revision: Option<&str>) -> ProjectModelSection {
    match crate::repository_inventory::build_repository_inventory(scope_root) {
        Ok(inventory) => ProjectModelSection {
            key: "inventory".to_string(),
            origin: ProjectModelSectionOrigin::Local,
            summary: format!(
                "{} files · languages {} · frameworks {}",
                inventory.source_files.len(),
                join_language_names(&inventory.languages),
                join_framework_names(&inventory.frameworks)
            ),
            source_path: None,
            content_hash: Some(value_hash(&inventory)),
            built_at_revision: current_revision.map(str::to_string),
            stale: false,
        },
        Err(error) => missing_section(
            "inventory",
            format!("inventory unavailable: {error}"),
            current_revision,
        ),
    }
}

fn attack_surface_section(scope_root: &Path, current_revision: Option<&str>) -> ProjectModelSection {
    match crate::attack_surface::build_attack_surface_map(scope_root) {
        Ok(surface) => ProjectModelSection {
            key: "attack-surface".to_string(),
            origin: ProjectModelSectionOrigin::Local,
            summary: format!(
                "{} surfaces · {} high risk · max {}",
                surface.summary.total, surface.summary.high_risk, surface.summary.max_risk_score
            ),
            source_path: None,
            content_hash: Some(value_hash(&surface)),
            built_at_revision: current_revision.map(str::to_string),
            stale: false,
        },
        Err(error) => missing_section(
            "attack-surface",
            format!("attack surface unavailable: {error}"),
            current_revision,
        ),
    }
}

fn missing_section(
    key: &str,
    summary: String,
    current_revision: Option<&str>,
) -> ProjectModelSection {
    ProjectModelSection {
        key: key.to_string(),
        origin: ProjectModelSectionOrigin::Missing,
        summary,
        source_path: None,
        content_hash: None,
        built_at_revision: current_revision.map(str::to_string),
        stale: false,
    }
}

fn section_is_stale(
    root: &Path,
    section: &ProjectModelSection,
    current_revision: Option<&str>,
) -> bool {
    revision_is_stale(section.built_at_revision.as_deref(), current_revision)
        || source_hash_changed(root, section)
}

fn revision_is_stale(built_at_revision: Option<&str>, current_revision: Option<&str>) -> bool {
    matches!(
        (built_at_revision, current_revision),
        (Some(built), Some(current)) if built != current
    )
}

fn source_hash_changed(root: &Path, section: &ProjectModelSection) -> bool {
    let (Some(source_path), Some(content_hash)) =
        (section.source_path.as_deref(), section.content_hash.as_deref())
    else {
        return false;
    };
    fs::read_to_string(root.join(source_path))
        .map(|body| crate::static_evidence::static_content_hash(&body) != content_hash)
        .unwrap_or(true)
}

#[cfg(test)]
mod tests;
