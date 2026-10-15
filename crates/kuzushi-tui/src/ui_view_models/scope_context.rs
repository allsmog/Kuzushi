//! Exact context associations projected from the study draft and frozen receipt.
use crate::app::BatchScanConfig;
use kuzushi_core::capabilities::campaign::ScopeStudyCaseInput;
use serde_json::Value;

pub(crate) fn selected_case(config: &BatchScanConfig) -> Option<&ScopeStudyCaseInput> {
    let index = config.scope_context.cursor.checked_sub(1)?;
    config.study.scope_draft.as_ref()?.cases.get(index)
}

pub(crate) fn rows(config: &BatchScanConfig) -> Vec<String> {
    let mut rows = vec!["Common context".into()];
    if let Some(draft) = &config.study.scope_draft {
        rows.extend(draft.cases.iter().map(|case| {
            format!(
                "{} · {}",
                case_label(config, &case.scope_id),
                binding_label(case)
            )
        }));
    }
    rows
}

pub(crate) fn case_label<'a>(config: &'a BatchScanConfig, scope_id: &'a str) -> &'a str {
    config
        .scope_context
        .labels
        .get(scope_id)
        .map(String::as_str)
        .unwrap_or(scope_id)
}

pub(crate) fn binding_label(case: &ScopeStudyCaseInput) -> &'static str {
    match &case.threat_model_ref {
        None => "inherits common",
        Some(Value::Null) => "omitted",
        Some(_) => "exact override",
    }
}

pub(crate) fn detail(config: &BatchScanConfig, width: usize) -> Vec<String> {
    let mut lines = selection_detail(config);
    if let Some(notice) = &config.notice {
        lines.insert(0, notice.clone());
    }
    lines
        .into_iter()
        .flat_map(|line| super::study_context::context_wrap(&line, width.max(1)))
        .collect()
}

fn selection_detail(config: &BatchScanConfig) -> Vec<String> {
    let Some(case) = selected_case(config) else {
        return common_detail(config);
    };
    let mut lines = vec![
        format!("Boundary: {} · {} passes", case_label(config, &case.scope_id), case.passes),
        format!("Context association: {}", binding_label(case)),
        "Enter inspects or chooses an exact revision for this boundary. i inherits common; o explicitly omits context.".into(),
        "Selection does not activate a global context or change sibling overrides. Changes require a new plan approval; spending remains.".into(),
    ];
    lines.push(format!("Boundary id: {}", case.scope_id));
    append_reference(
        &mut lines,
        "Draft effective context",
        effective_context(config, case),
    );
    append_frozen_case(&mut lines, config, case);
    lines
}

fn common_detail(config: &BatchScanConfig) -> Vec<String> {
    let mut lines = vec![
        "Common context for inheriting boundaries".into(),
        "Enter opens the exact revision picker. Common changes affect inheriting boundaries; exact overrides and explicit omissions remain.".into(),
        "An unset draft selection is frozen during preparation. Inspect the prepared plan before approval.".into(),
    ];
    append_reference(
        &mut lines,
        "Common draft context",
        config
            .study
            .scan_input
            .as_ref()
            .and_then(|input| input.get("threatModelRef")),
    );
    if let Some(receipt) = &config.study.scope_receipt {
        append_reference(
            &mut lines,
            "Frozen common context",
            Some(&receipt.scope_study.inherited_threat_model_ref),
        );
        lines.push(format!("Frozen plan: {}", receipt.plan_sha256));
    }
    lines
}

fn effective_context<'a>(
    config: &'a BatchScanConfig,
    case: &'a ScopeStudyCaseInput,
) -> Option<&'a Value> {
    case.threat_model_ref
        .as_ref()
        .or_else(|| config.study.scan_input.as_ref()?.get("threatModelRef"))
}

fn append_frozen_case(
    lines: &mut Vec<String>,
    config: &BatchScanConfig,
    case: &ScopeStudyCaseInput,
) {
    let Some(receipt) = &config.study.scope_receipt else {
        lines.push(
            "Draft only. Prepare to freeze source, exact context and membership before approval."
                .into(),
        );
        return;
    };
    let Some(frozen) = receipt
        .scope_study
        .cases
        .iter()
        .find(|frozen| frozen.id == case.scope_id)
    else {
        return;
    };
    append_reference(
        lines,
        "Context actually frozen for scans",
        frozen.base_input.get("threatModelRef"),
    );
    append_source(
        lines,
        &serde_json::json!(frozen.equivalence.components.target_git),
        &frozen.equivalence.components.workspace_identity,
    );
    lines.push(format!(
        "Scope reference: {}",
        frozen.base_input["scanScopeRef"]
    ));
}

fn append_source(lines: &mut Vec<String>, git: &Value, identity: &str) {
    lines.push(format!(
        "Source SHA: {}",
        git["sha"].as_str().unwrap_or("unavailable")
    ));
    let state = match git["dirty"].as_bool() {
        Some(true) => "changed from commit; this plan records the frozen worktree",
        Some(false) => "clean at preparation",
        None => "Git state unavailable; use the frozen source identity",
    };
    lines.push(format!("Source state: {state}"));
    lines.push(format!("Source identity: {identity}"));
}

pub(crate) fn reading_controls(width: u16, offset: usize, max: usize) -> String {
    let label = if width < 60 {
        "↑↓ Enter choose · PgUp/Dn"
    } else {
        "↑↓ boundary · Enter choose · PgUp/PgDn"
    };
    format!("{label} {}/{}", offset + 1, max + 1)
}

fn append_reference(lines: &mut Vec<String>, label: &str, reference: Option<&Value>) {
    match reference {
        None => lines.push(format!("{label}: unset; preparation must resolve it")),
        Some(Value::Null) => lines.push(format!("{label}: explicitly omitted")),
        Some(reference) => lines.extend([
            format!(
                "{label}: {}",
                reference["revisionId"]
                    .as_str()
                    .unwrap_or("invalid reference")
            ),
            format!(
                "Context digest: {}",
                reference["sha256"].as_str().unwrap_or("unavailable")
            ),
        ]),
    }
}

pub(crate) fn controls(width: u16) -> [&'static str; 2] {
    if width < 60 {
        [
            "↑↓ select · Enter choose · PgUp/Dn",
            "i inherit · o omit · Esc back",
        ]
    } else {
        [
            "↑↓ boundary · Enter inspect / choose · PgUp/PgDn read",
            "i inherit common · o omit for boundary · Esc back",
        ]
    }
}
