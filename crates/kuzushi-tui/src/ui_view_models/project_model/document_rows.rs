use super::{ProjectModelOrigin, ProjectModelRow};
use crate::ShellApp;

pub(super) fn project_model_document_rows(app: &ShellApp) -> Option<Vec<ProjectModelRow>> {
    let target = app.target.as_ref()?;
    let scope_id = app
        .active_scope
        .as_ref()
        .map(|scope| scope.id.as_str())
        .unwrap_or(kuzushi_core::ROOT_SCOPE_ID);
    let revision = app
        .workbench_cache
        .borrow_mut()
        .git_metadata(Some(target.as_path()))
        .map(|git| git.sha);
    let document = kuzushi_core::load_project_model_document(target, scope_id, revision.as_deref())
        .ok()
        .flatten()?;
    Some(document.sections.iter().map(document_section_row).collect())
}

fn document_section_row(section: &kuzushi_core::ProjectModelSection) -> ProjectModelRow {
    ProjectModelRow {
        section: document_section_label(&section.key),
        origin: document_section_origin(section),
        state: document_section_state(section),
        summary: section.summary.clone(),
        action: document_section_action(&section.key),
    }
}

fn document_section_label(key: &str) -> &'static str {
    match key {
        "context-feed" => "context feed",
        "inventory" => "inventory",
        "threat-model" => "threat model",
        "attack-surface" => "attack surface",
        _ => "project section",
    }
}

fn document_section_origin(section: &kuzushi_core::ProjectModelSection) -> ProjectModelOrigin {
    if section.stale {
        return ProjectModelOrigin::Stale;
    }
    match section.origin {
        kuzushi_core::ProjectModelSectionOrigin::Inherited => ProjectModelOrigin::Inherited,
        kuzushi_core::ProjectModelSectionOrigin::Local => ProjectModelOrigin::Local,
        kuzushi_core::ProjectModelSectionOrigin::Missing => ProjectModelOrigin::Missing,
    }
}

fn document_section_state(section: &kuzushi_core::ProjectModelSection) -> &'static str {
    if section.stale {
        return "stale";
    }
    match section.origin {
        kuzushi_core::ProjectModelSectionOrigin::Inherited => "inherited",
        kuzushi_core::ProjectModelSectionOrigin::Local => "present",
        kuzushi_core::ProjectModelSectionOrigin::Missing => "missing",
    }
}

fn document_section_action(key: &str) -> &'static str {
    match key {
        "context-feed" | "inventory" => "context build",
        "threat-model" => "threats summary",
        "attack-surface" => "project model",
        _ => "project model",
    }
}
