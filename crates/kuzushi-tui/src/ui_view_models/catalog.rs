use crate::ShellApp;
use kuzushi_core::modules::ModuleKind;
use std::collections::BTreeMap;

pub(crate) const CATALOG_CATEGORY_ORDER: &[&str] = &["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogModel {
    pub(crate) module_count: usize,
    pub(crate) default_action: Option<CatalogActionModule>,
    pub(crate) groups: Vec<CatalogModuleGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogActionModule {
    pub(crate) id: String,
    pub(crate) description: String,
    category: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogModuleGroup {
    pub(crate) category: &'static str,
    pub(crate) rows: Vec<CatalogModuleRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogModuleRow {
    pub(crate) id: String,
    pub(crate) description: String,
    pub(crate) focused: bool,
}

pub(crate) fn catalog_model(app: &ShellApp) -> CatalogModel {
    let modules = catalog_modules(app);
    let module_count = modules.len();
    let default_action = preferred_default_module(&modules).cloned();
    let cursor_id = selected_cursor_id(app, &modules);
    let focused_id = app.focused_module.as_deref();
    CatalogModel {
        module_count,
        default_action,
        groups: catalog_groups(&modules, focused_id, cursor_id.as_deref()),
    }
}

fn catalog_modules(app: &ShellApp) -> Vec<CatalogActionModule> {
    app.registry
        .modules()
        .map(|module| {
            let metadata = module.metadata();
            CatalogActionModule {
                id: metadata.id.clone(),
                description: metadata.description.clone(),
                category: catalog_category(&metadata.id, metadata.kind),
            }
        })
        .collect()
}

fn preferred_default_module(modules: &[CatalogActionModule]) -> Option<&CatalogActionModule> {
    modules
        .iter()
        .find(|module| module.id == "sast")
        .or_else(|| modules.iter().find(|module| module.id == "semgrep"))
        .or_else(|| modules.first())
}

fn selected_cursor_id(app: &ShellApp, modules: &[CatalogActionModule]) -> Option<String> {
    let visible_ids = ordered_visible_module_ids(modules);
    visible_ids
        .get(app.catalog_cursor.min(visible_ids.len().saturating_sub(1)))
        .cloned()
}

fn ordered_visible_module_ids(modules: &[CatalogActionModule]) -> Vec<String> {
    catalog_groups(modules, None, None)
        .into_iter()
        .flat_map(|group| group.rows.into_iter().map(|row| row.id))
        .collect()
}

fn catalog_groups(
    modules: &[CatalogActionModule],
    focused_id: Option<&str>,
    cursor_id: Option<&str>,
) -> Vec<CatalogModuleGroup> {
    let mut grouped: BTreeMap<&'static str, Vec<CatalogModuleRow>> = BTreeMap::new();
    for module in modules {
        grouped
            .entry(module.category)
            .or_default()
            .push(module_row(module, focused_id, cursor_id));
    }
    CATALOG_CATEGORY_ORDER
        .iter()
        .filter_map(|category| group_from_rows(*category, grouped.remove(category)))
        .collect()
}

fn module_row(
    module: &CatalogActionModule,
    focused_id: Option<&str>,
    cursor_id: Option<&str>,
) -> CatalogModuleRow {
    CatalogModuleRow {
        id: module.id.clone(),
        description: module.description.clone(),
        focused: focused_id == Some(module.id.as_str()) || cursor_id == Some(module.id.as_str()),
    }
}

fn group_from_rows(
    category: &'static str,
    rows: Option<Vec<CatalogModuleRow>>,
) -> Option<CatalogModuleGroup> {
    rows.map(|rows| CatalogModuleGroup { category, rows })
}

fn catalog_category(id: &str, kind: ModuleKind) -> &'static str {
    match id {
        "semgrep"
        | "sast"
        | "codeql"
        | "agentic-sast"
        | "carlini-threat-hunt"
        | "secret-scan"
        | "iac-scan"
        | "dep-hygiene"
        | "taint-iris"
        | "taint-iris-next"
        | "systems-hunt"
        | "chrome-rce"
        | "prompt-armor"
        | "vuln-scout"
        | "tob" => "OFFENSE",
        "context" | "context-lite" | "recon" | "threat-model" | "randori" | "x-ray" | "ndiff"
        | "workspace" => "INTEL",
        "triage" | "verify" | "patch" | "findings" => "DEFENSE",
        _ => module_category(kind),
    }
}

fn module_category(kind: ModuleKind) -> &'static str {
    match kind {
        ModuleKind::Offense | ModuleKind::Scan => "OFFENSE",
        ModuleKind::Intel | ModuleKind::Context | ModuleKind::Workspace => "INTEL",
        ModuleKind::Governance | ModuleKind::Config | ModuleKind::Catalog => "GOVERNANCE",
        ModuleKind::Defense | ModuleKind::Findings | ModuleKind::Triage => "DEFENSE",
        ModuleKind::Internal => "GOVERNANCE",
    }
}
