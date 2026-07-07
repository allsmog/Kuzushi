use super::context_snapshot_state;
use crate::ShellApp;
use kuzushi_core::modules::ModuleKind;
use kuzushi_core::Severity;
use std::collections::BTreeMap;

pub(crate) const CATALOG_CATEGORY_ORDER: &[&str] = &["OFFENSE", "INTEL", "GOVERNANCE", "DEFENSE"];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogModel {
    pub(crate) module_count: usize,
    pub(crate) expanded: bool,
    pub(crate) default_action: Option<CatalogActionModule>,
    pub(crate) collapsed: CatalogCollapsedModel,
    pub(crate) groups: Vec<CatalogModuleGroup>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogActionModule {
    id: String,
    description: String,
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
    pub(crate) cells: [String; 2],
    pub(crate) focused: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogCollapsedModel {
    pub(crate) target_warning: Option<&'static str>,
    pub(crate) next_hint: String,
    pub(crate) scan_hint: Option<String>,
    pub(crate) scan_command: &'static str,
}

pub(crate) fn catalog_model(app: &ShellApp) -> CatalogModel {
    let modules = catalog_modules(app);
    let module_count = modules.len();
    let default_action = preferred_default_module(&modules).cloned();
    let cursor_id = selected_cursor_id(app, &modules);
    let focused_id = app.focused_module.as_deref();
    CatalogModel {
        module_count,
        expanded: app.catalog_route.is_expanded(),
        default_action,
        collapsed: collapsed_catalog_model(app),
        groups: catalog_groups(&modules, focused_id, cursor_id.as_deref()),
    }
}

pub(crate) fn catalog_uses_collapsed_layout(model: &CatalogModel, width: u16) -> bool {
    !model.expanded && compact_catalog_width(width)
}

pub(crate) fn catalog_default_action_hint(module: &CatalogActionModule, width: u16) -> String {
    let prefix = format!("Run {} — ", module.id);
    let budget = default_action_description_budget(width, &prefix);
    format!(
        "{prefix}{}",
        short_catalog_sentence(&module.description, budget)
    )
}

fn default_action_description_budget(width: u16, prefix: &str) -> usize {
    (width as usize)
        .saturating_sub(prefix.chars().count() + 8)
        .max(40)
}

fn short_catalog_sentence(value: &str, max_chars: usize) -> String {
    let first = value.split('.').next().unwrap_or(value).trim();
    fit_catalog_text(first, max_chars)
}

fn fit_catalog_text(value: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    if value.chars().count() <= max_chars {
        return value.to_string();
    }
    if max_chars <= 3 {
        return value.chars().take(max_chars).collect();
    }
    let mut truncated = value
        .chars()
        .take(max_chars.saturating_sub(3))
        .collect::<String>();
    truncated.push_str("...");
    truncated
}

fn compact_catalog_width(width: u16) -> bool {
    width < 96
}

fn collapsed_catalog_model(app: &ShellApp) -> CatalogCollapsedModel {
    CatalogCollapsedModel {
        target_warning: collapsed_target_warning(app),
        next_hint: catalog_next_hint(app),
        scan_hint: app.findings.is_empty().then(|| app.first_finding_hint()),
        scan_command: app.first_finding_scan_command(),
    }
}

fn collapsed_target_warning(app: &ShellApp) -> Option<&'static str> {
    if app.target.is_none() {
        return Some("[!] no target selected; run `target .`, then `next`");
    }
    app.findings
        .is_empty()
        .then_some("[!] active target has no persisted findings yet")
}

fn catalog_next_hint(app: &ShellApp) -> String {
    match context_snapshot_state(app) {
        "missing" => {
            return "Build the context snapshot with `context build` so SAST has structure to walk."
                .to_string();
        }
        "malformed" => {
            return "Context snapshot is malformed; rerun `context build` before scanning."
                .to_string();
        }
        _ => {}
    }
    critical_finding_hint(app)
        .or_else(|| findings_waiting_hint(app))
        .unwrap_or_else(|| app.first_finding_hint())
}

fn critical_finding_hint(app: &ShellApp) -> Option<String> {
    has_critical_finding(app)
        .then(|| super::findings::cached_sorted_finding_alias_indices(app).into_iter().next())
        .flatten()
        .map(|(alias, _)| {
            format!(
                "Drill in: `open {alias}` for the highest-severity finding · `findings` for the list."
            )
        })
}

fn findings_waiting_hint(app: &ShellApp) -> Option<String> {
    (!app.findings.is_empty()).then(|| {
        let count = app.findings.len();
        format!(
            "{count} {} waiting · `findings` to triage · `threats regen` for STRIDE refresh.",
            if count == 1 { "finding" } else { "findings" }
        )
    })
}

fn has_critical_finding(app: &ShellApp) -> bool {
    app.findings
        .iter()
        .any(|finding| finding.severity == Severity::Critical)
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
        .get(
            app.catalog_route
                .cursor()
                .min(visible_ids.len().saturating_sub(1)),
        )
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
        cells: [module.id.clone(), module.description.clone()],
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
        | "license-scan"
        | "cargo-audit"
        | "govulncheck"
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

#[cfg(test)]
mod tests;
