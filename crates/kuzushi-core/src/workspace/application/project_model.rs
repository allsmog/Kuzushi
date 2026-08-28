use super::*;
use crate::workspace::inventory::repo_relative;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod formatting;
use formatting::{
    default_project_model_schema_version, join_framework_names, join_language_names, value_hash,
};

pub const PROJECT_MODEL_SCHEMA_VERSION: u32 = 1;
const MAX_PROJECT_MODEL_BYTES: usize = 32 * 1024 * 1024;
const MAX_PROJECT_MODEL_SOURCE_BYTES: usize = 16 * 1024 * 1024;

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
    let tree =
        load_nested_project_scopes(root)?.unwrap_or_else(|| discover_nested_project_scopes(root));
    build_project_model_document_from_tree(root, &tree, scope_id, current_revision)
}

pub fn load_project_model_document(
    root: impl AsRef<Path>,
    scope_id: &str,
    current_revision: Option<&str>,
) -> Result<Option<ProjectModelDocument>> {
    let root = root.as_ref();
    validate_scope_id(scope_id)?;
    let path = project_model_scope_path(root, scope_id);
    let Some(body) = read_optional_workspace_text(root, &path, MAX_PROJECT_MODEL_BYTES)? else {
        return Ok(None);
    };
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
    let root = root.as_ref();
    validate_scope_id(&document.scope_id)?;
    let path = project_model_scope_path(root, &document.scope_id);
    let body =
        serde_json::to_string_pretty(document).context("Could not serialize project model")?;
    let relative = path
        .strip_prefix(root)
        .context("Project model path escaped the workspace")?;
    write_workspace_state_file(root, relative, body.as_bytes())?;
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
    ProjectModelBuilder::new(root, tree, current_revision).build(scope_id)
}

struct ProjectModelBuilder<'a> {
    root: &'a Path,
    tree: &'a NestedProjectScopeTree,
    current_revision: Option<String>,
    memo: BTreeMap<String, ProjectModelDocument>,
    visiting: BTreeSet<String>,
}

impl<'a> ProjectModelBuilder<'a> {
    fn new(
        root: &'a Path,
        tree: &'a NestedProjectScopeTree,
        current_revision: Option<String>,
    ) -> Self {
        Self {
            root,
            tree,
            current_revision,
            memo: BTreeMap::new(),
            visiting: BTreeSet::new(),
        }
    }

    fn build(&mut self, scope_id: &str) -> Result<ProjectModelDocument> {
        if let Some(document) = self.memo.get(scope_id) {
            return Ok(document.clone());
        }
        if !self.visiting.insert(scope_id.to_string()) {
            anyhow::bail!("cyclic project scope parent chain at {scope_id:?}");
        }
        let result = self.build_uncached(scope_id);
        self.visiting.remove(scope_id);
        let document = result?;
        self.memo.insert(scope_id.to_string(), document.clone());
        Ok(document)
    }

    fn build_uncached(&mut self, scope_id: &str) -> Result<ProjectModelDocument> {
        let scope = self
            .tree
            .scopes
            .iter()
            .find(|scope| scope.id == scope_id)
            .cloned()
            .with_context(|| format!("unknown project scope {scope_id:?}"))?;
        let mut sections = self.inherited_sections(&scope)?;
        let scope_root = checked_scope_root(self.root, &scope)?;
        merge_local_sections(
            &mut sections,
            local_sections(self.root, &scope_root, self.current_revision.as_deref()),
        );
        Ok(ProjectModelDocument {
            schema_version: PROJECT_MODEL_SCHEMA_VERSION,
            scope_id: scope.id.clone(),
            scope_path: scope.rel_path.clone(),
            built_at_revision: self.current_revision.clone(),
            sections: sections.into_values().collect(),
        })
    }

    fn inherited_sections(
        &mut self,
        scope: &NestedProjectScope,
    ) -> Result<BTreeMap<String, ProjectModelSection>> {
        let Some(parent_id) = scope.parent.as_deref() else {
            return Ok(BTreeMap::new());
        };
        let parent = self.build(parent_id)?;
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
    match read_optional_workspace_text(root, source_path, MAX_PROJECT_MODEL_SOURCE_BYTES) {
        Ok(Some(body)) => ProjectModelSection {
            key: key.to_string(),
            origin: ProjectModelSectionOrigin::Local,
            summary: format!("{label} present"),
            source_path: Some(repo_relative(root, source_path)),
            content_hash: Some(crate::static_evidence::static_content_hash(&body)),
            built_at_revision: current_revision.map(str::to_string),
            stale: false,
        },
        Ok(None) => missing_section(key, format!("{label} missing"), current_revision),
        Err(error) => missing_section(
            key,
            format!("{label} unavailable: {error}"),
            current_revision,
        ),
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

fn attack_surface_section(
    scope_root: &Path,
    current_revision: Option<&str>,
) -> ProjectModelSection {
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
    let (Some(source_path), Some(content_hash)) = (
        section.source_path.as_deref(),
        section.content_hash.as_deref(),
    ) else {
        return false;
    };
    read_optional_workspace_text(
        root,
        &root.join(source_path),
        MAX_PROJECT_MODEL_SOURCE_BYTES,
    )
    .ok()
    .flatten()
    .is_none_or(|body| crate::static_evidence::static_content_hash(&body) != content_hash)
}

fn validate_scope_id(scope_id: &str) -> Result<()> {
    anyhow::ensure!(
        crate::workspace::domain::valid_scope_id(scope_id),
        "Invalid project scope id {scope_id:?}"
    );
    Ok(())
}

fn checked_scope_root(root: &Path, scope: &NestedProjectScope) -> Result<PathBuf> {
    if scope.rel_path == "." {
        return Ok(root.to_path_buf());
    }
    let normalized = normalize_relative_path(&scope.rel_path)
        .with_context(|| format!("Invalid project scope path {:?}", scope.rel_path))?;
    anyhow::ensure!(
        normalized == scope.rel_path,
        "Project scope path is not normalized: {:?}",
        scope.rel_path
    );
    let path = validated_workspace_descendant(root, &normalized)?;
    let metadata = fs::symlink_metadata(&path)
        .with_context(|| format!("Could not inspect project scope {}", path.display()))?;
    anyhow::ensure!(
        metadata.is_dir(),
        "Project scope is not a directory: {}",
        path.display()
    );
    Ok(path)
}

#[cfg(test)]
mod tests;
