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
    lines.extend(super::context_description_body(config));
    lines.push("Recorded source and configuration are checked again before approval and execution. Missing a finding in a later pass does not establish a fix.".into());
    lines.push(
        "Tab shows recorded engine inputs, readable settings, then exact JSON and supplemental context.".into(),
    );
    lines
}

pub(crate) fn context_reference_summary(input: &Value) -> String {
    let Some(reference) = input.get("threatModelRef") else {
        return "legacy selection; no explicit reference recorded".into();
    };
    if reference.is_null() {
        return "explicitly omitted".into();
    }
    match recorded_reference(reference) {
        Ok(reference) => format!(
            "{} · revision {}. JSON has the exact content hash.",
            reference.model_id, reference.revision_id
        ),
        Err(_) => {
            "recorded reference is malformed; inspect JSON before preparing a new draft".into()
        }
    }
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
    if input["scanContextRef"].is_null() {
        return "Supplemental context: explicitly omitted.".into();
    }
    "Supplemental context: reference recorded, but exact text is unavailable.".into()
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
