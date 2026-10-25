use crate::app::{ShellApp, ViewDataState};
use kuzushi_core::modules::{ExecutableRequirement, ModuleMaturity, ScanTaskPreview};
use serde_json::Value;

pub(crate) struct EngineReadiness {
    pub badge: &'static str,
    pub suffix: &'static str,
    pub details: Vec<String>,
    requirements: Vec<ExecutableRequirement>,
}

pub(super) fn automatic() -> EngineReadiness {
    unassessed("Automatic defaults are resolved during preparation. Unavailable optional engines are disclosed in the plan and run receipt.")
}

pub(super) fn unregistered() -> EngineReadiness {
    unassessed("Readiness unassessed: this saved engine has no registered task.")
}

fn unassessed(detail: &str) -> EngineReadiness {
    EngineReadiness {
        badge: "",
        suffix: "",
        details: vec![detail.into()],
        requirements: Vec::new(),
    }
}

pub(super) fn task_readiness(app: &ShellApp, task: &str, input: &Value) -> EngineReadiness {
    let preview = match app.registry().scan_task_preview(task, input) {
        Ok(preview) => preview,
        Err(error) => return unassessed(&format!("Readiness unavailable: {error:#}")),
    };
    let mut readiness = described_route(&preview);
    readiness
        .details
        .insert(0, format!("CHECKS PENDING: {}", preview.deferred_checks));
    append_dependency_status(app, &mut readiness);
    if model_missing(app, &preview, input) {
        readiness.suffix = " · model required";
        readiness.details.insert(0, "PREREQUISITE MISSING: select an explicit model in the study's Model row. Credentials and runtime compatibility are checked during preparation; no fallback is used.".into());
    }
    readiness
}

fn described_route(preview: &ScanTaskPreview) -> EngineReadiness {
    let (badge, label) = match preview.maturity {
        ModuleMaturity::Core => ("", "Core"),
        ModuleMaturity::Labs => ("[Labs] ", "Experimental (Labs)"),
        ModuleMaturity::Compatibility => ("[Compat] ", "Compatibility"),
    };
    let route = if preview.native {
        format!("Runs as a native scan task. Catalog reference: {}. Scan-task settings and receipts apply.", preview.tool)
    } else {
        format!("Model-backed SAST route: {}.", preview.tool)
    };
    EngineReadiness {
        badge,
        suffix: "",
        details: vec![
            format!("Catalog: {label}. Target readiness is checked separately."),
            route,
        ],
        requirements: preview.executables.clone(),
    }
}

fn append_dependency_status(app: &ShellApp, readiness: &mut EngineReadiness) {
    if readiness.requirements.is_empty() {
        return;
    }
    let (suffix, detail) = dependency_status(app, &readiness.requirements);
    readiness.suffix = suffix;
    append_presence_detail(readiness, detail);
}

fn append_presence_detail(readiness: &mut EngineReadiness, detail: String) {
    if !readiness.suffix.is_empty() {
        readiness.details.insert(0, detail);
        return;
    }
    readiness.details.push(detail);
}

fn dependency_status(
    app: &ShellApp,
    requirements: &[ExecutableRequirement],
) -> (&'static str, String) {
    let Some(target) = app.target() else {
        return unchecked_dependencies();
    };
    let cache = app.workbench_cache().borrow();
    let key = cache.executable_options_key(requirements.to_vec());
    match cache.cached_executable_options(target, &key) {
        ViewDataState::Ready(missing) => checked_dependencies(&missing),
        _ => unchecked_dependencies(),
    }
}

fn checked_dependencies(missing: &[String]) -> (&'static str, String) {
    if missing.is_empty() {
        return ("", "Executable found (presence only). Compatibility and source prerequisites remain unchecked.".into());
    }
    (" · dependency missing", format!("DEPENDENCY MISSING: {}. Configure the executable or install it, then press r to recheck. No command runs during this check.", missing.join(", ")))
}

fn unchecked_dependencies() -> (&'static str, String) {
    (
        "",
        "DEPENDENCIES UNCHECKED: background presence check pending. No command is invoked.".into(),
    )
}

fn model_missing(app: &ShellApp, preview: &ScanTaskPreview, input: &Value) -> bool {
    preview.runtime_required
        && input["model"]
            .as_str()
            .or(app.config().model.as_deref())
            .is_none_or(|model| model.trim().is_empty())
}

pub(crate) fn selected_engine_requirements(app: &ShellApp) -> Vec<ExecutableRequirement> {
    let Some(picker) = app.study_engine_picker() else {
        return Vec::new();
    };
    super::engine_rows(app)
        .into_iter()
        .nth(picker.cursor)
        .map_or_else(Vec::new, |row| row.readiness.requirements)
}
