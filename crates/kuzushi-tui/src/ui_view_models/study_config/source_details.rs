use crate::app::{BatchScanConfig, StudySourceView};
use kuzushi_core::capabilities::campaign::BatchEquivalenceComponents;
use serde_json::Value;

pub(super) fn source_lines(config: &BatchScanConfig) -> Vec<String> {
    match config.source_view.selected {
        StudySourceView::Overview => overview_lines(config),
        StudySourceView::Inputs => input_lines(config),
        StudySourceView::Settings => setting_lines(config),
        StudySourceView::Options => option_lines(config),
    }
}

fn overview_lines(config: &BatchScanConfig) -> Vec<String> {
    let mut lines = vec!["SOURCE OVERVIEW".into()];
    lines.extend(draft_context_lines(config));
    lines.extend(super::context_description_body(config));
    lines.push("Recorded source and configuration are checked again before approval and execution. Missing a finding in a later pass does not establish a fix.".into());
    lines.push(
        "Tab shows recorded engine inputs, readable settings, then exact JSON and supplemental context.".into(),
    );
    lines
}

fn draft_context_lines(config: &BatchScanConfig) -> Vec<String> {
    if config.study.plan_identity().is_some() {
        return Vec::new();
    }
    let Some(input) = config.study.scan_input.as_ref() else {
        return Vec::new();
    };
    vec![
        format!("Draft context: {}", draft_context_summary(input)),
        "This selection is not frozen or approved. Enter inspects its exact content before planning.".into(),
    ]
}

fn draft_context_summary(input: &Value) -> String {
    let Some(reference) = input.get("threatModelRef") else {
        return context_reference_summary(input);
    };
    if reference.is_null() {
        return "explicitly omitted".into();
    }
    reference_identity(reference)
        .unwrap_or_else(|_| "malformed reference; choose a valid context before planning".into())
}

pub(crate) fn context_reference_summary(input: &Value) -> String {
    if let Some(reference) = input.get("threatModelRef") {
        return reference_summary(reference);
    }
    input.get("inheritedContextRef").map_or_else(
        || "legacy selection; no explicit reference recorded".into(),
        |reference| format!("inherited {}", reference_summary(reference)),
    )
}

fn reference_summary(reference: &Value) -> String {
    if reference.is_null() {
        return "explicitly omitted".into();
    }
    match reference_identity(reference) {
        Ok(identity) => format!("{identity}. JSON has the exact content hash."),
        Err(_) => {
            "recorded reference is malformed; inspect JSON before preparing a new draft".into()
        }
    }
}

fn reference_identity(value: &Value) -> anyhow::Result<String> {
    let reference = recorded_reference(value)?;
    Ok(format!(
        "{} · revision {}",
        reference.model_id, reference.revision_id
    ))
}

fn recorded_reference(value: &Value) -> anyhow::Result<kuzushi_core::ThreatModelRef> {
    let reference: kuzushi_core::ThreatModelRef = serde_json::from_value(value.clone())?;
    kuzushi_core::ThreatModelId::parse(reference.model_id.as_str())?;
    kuzushi_core::ThreatModelRevisionId::parse(reference.revision_id.as_str())?;
    Ok(reference)
}

fn input_lines(config: &BatchScanConfig) -> Vec<String> {
    let mut lines = vec!["RECORDED ENGINE INPUTS".into()];
    for condition in conditions(config) {
        lines.push(format!("Case: {}", condition.label));
        lines.extend(super::engine_inputs::source_lines(condition.components));
    }
    if lines.len() == 1 {
        lines.push("No frozen engine identities. Prepare the draft to record them.".into());
        return lines;
    }
    lines.push("Location and recorded content guard comparison drift; they do not establish engine health or useful coverage. Automatic execution may skip optional engines; inspect its receipt.".into());
    lines.push("Current inspection limits: 100,000 entries and 512 MiB per condition across executables, CPG caches and overrides; 128 MiB per engine file and 16 MiB per override file; a 30-second deadline checked between reads. Cases repeat inspection. Source, managed CodeQL database authentication and scanner work use separate checks.".into());
    lines
}

fn option_lines(config: &BatchScanConfig) -> Vec<String> {
    let mut lines = vec!["EXACT PREPARED OPTIONS".into()];
    for condition in conditions(config) {
        lines.push(format!("Case: {}", condition.label));
        lines.extend(pretty_options(condition.input));
        lines.extend(super::supporting_context_lines(
            condition.input,
            condition.supporting_context,
        ));
    }
    if lines.len() == 1 {
        lines.push("No frozen options. Prepare the draft before reviewing exact bindings.".into());
    }
    lines
}

fn setting_lines(config: &BatchScanConfig) -> Vec<String> {
    let mut lines = vec!["PREPARED SETTINGS".into()];
    lines.push("Read-only values from the frozen plan. Help uses current tool descriptors. Tab JSON shows the complete prepared input; reading changes no options or approval.".into());
    for condition in conditions(config) {
        lines.push(format!("Case: {}", condition.label));
        lines.extend(super::prepared_settings::settings_lines(
            condition.input,
            &config.source_option_specs,
        ));
    }
    if lines.len() == 2 {
        lines
            .push("No frozen settings. Prepare the draft before reviewing recorded values.".into());
    }
    lines
}

fn pretty_options(input: &Value) -> Vec<String> {
    match serde_json::to_string_pretty(input) {
        Ok(text) => text.lines().map(str::to_owned).collect(),
        Err(error) => vec![format!("Recorded options could not be formatted: {error}")],
    }
}

pub(crate) fn supporting_context_summary(input: &Value, text: Option<&str>) -> String {
    if input.get("scanContextRef").is_none() {
        return "Supplemental context: legacy live selection; prepare a new draft to freeze it."
            .into();
    }
    if let Some(text) = text {
        return format!("Supplemental context: {} bytes recorded; JSON shows the exact text for the agentic adapter.", text.len());
    }
    frozen_context_omission(&input["scanContextRef"])
}

// Receipt loaders authenticate the referenced document before this projection.
// A successful inspection with no text records an empty frozen snapshot.
fn frozen_context_omission(reference: &Value) -> String {
    if reference.is_null() {
        return "Supplemental context: explicitly omitted.".into();
    }
    match serde_json::from_value::<kuzushi_core::scan::ScanContextRef>(reference.clone()) {
        Ok(reference) if reference.schema_version == 1 => {
            "Supplemental context: frozen snapshot contains no supplemental text.".into()
        }
        _ => "Supplemental context: reference recorded, but exact text is unavailable.".into(),
    }
}

struct SourceCondition<'a> {
    label: &'a str,
    input: &'a Value,
    components: &'a BatchEquivalenceComponents,
    supporting_context: Option<&'a str>,
}

fn conditions(config: &BatchScanConfig) -> impl Iterator<Item = SourceCondition<'_>> {
    let single = config.study.receipt.iter().map(|receipt| SourceCondition {
        label: "Study",
        input: &receipt.scan_input,
        components: &receipt.equivalence.components,
        supporting_context: receipt.supporting_context.as_deref(),
    });
    let scopes = config.study.scope_receipt.iter().flat_map(|receipt| {
        receipt
            .scope_study
            .cases
            .iter()
            .map(move |case| SourceCondition {
                label: &case.label,
                input: &case.base_input,
                components: &case.equivalence.components,
                supporting_context: receipt.supporting_context.as_deref(),
            })
    });
    let matrix = config.study.matrix.receipt.iter().flat_map(|receipt| {
        receipt
            .matrix
            .cases
            .iter()
            .map(move |case| SourceCondition {
                label: &case.label,
                input: &case.base_input,
                components: &case.equivalence.components,
                supporting_context: receipt.supporting_context.as_deref(),
            })
    });
    single.chain(scopes).chain(matrix)
}

pub(super) fn reader_title(config: &BatchScanConfig) -> &'static str {
    if config.selected_row() != crate::app::BatchScanConfigRow::Context {
        return config.selected_row().label();
    }
    match config.source_view.selected {
        StudySourceView::Overview => "Source and context: Overview",
        StudySourceView::Inputs => "Source and context: Inputs",
        StudySourceView::Settings => "Source and context: Settings",
        StudySourceView::Options => "Source and context: JSON",
    }
}

#[cfg(test)]
mod tests;
