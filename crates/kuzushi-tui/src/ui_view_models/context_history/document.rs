use super::*;

pub(crate) fn history_detail_lines(
    state: &ContextHistoryState,
    catalog: &ContextHistoryCatalog,
    width: usize,
) -> Vec<String> {
    let mut lines = Vec::new();
    if append_attention(&mut lines, state) {
        return wrapped(lines, width);
    }
    append_history_body(&mut lines, state, catalog);
    wrapped(lines, width)
}

fn append_attention(lines: &mut Vec<String>, state: &ContextHistoryState) -> bool {
    if let Some(notice) = &state.notice {
        lines.push(notice.clone());
    }
    if let Some(error) = &state.error {
        lines.push(format!("Attention: {error}"));
    }
    if state.error.is_some() && state.request.is_some() && state.data.is_none() {
        lines.push("Enter retries this local read. Esc returns to the selected revision.".into());
        return true;
    }
    false
}

fn append_history_body(
    lines: &mut Vec<String>,
    state: &ContextHistoryState,
    catalog: &ContextHistoryCatalog,
) {
    match &state.request {
        Some(ContextHistoryRequest::Read(reference)) => {
            lines.push(format!(
                "Inspect: {}",
                history_label(state, catalog, reference)
            ));
            append_read(lines, state);
        }
        Some(ContextHistoryRequest::Compare {
            baseline,
            candidate,
        }) => {
            lines.extend([
                format!("Before: {}", history_label(state, catalog, baseline)),
                format!("After: {}", history_label(state, catalog, candidate)),
            ]);
            append_comparison(lines, state.data.as_deref());
        }
        None => append_selection(lines, state, catalog),
    }
}

fn history_label(
    state: &ContextHistoryState,
    catalog: &ContextHistoryCatalog,
    reference: &ThreatModelRef,
) -> String {
    state
        .selected_label
        .as_ref()
        .filter(|_| state.selected.as_ref() == Some(reference))
        .or_else(|| {
            state
                .baseline_label
                .as_ref()
                .filter(|_| state.baseline.as_ref() == Some(reference))
        })
        .cloned()
        .unwrap_or_else(|| catalog.label(reference))
}

fn append_selection(
    lines: &mut Vec<String>,
    state: &ContextHistoryState,
    catalog: &ContextHistoryCatalog,
) {
    let Some(index) = catalog.selected_index(Some(state)) else {
        lines.push(
            "Select an available revision. Existing selection is retained without substitution."
                .into(),
        );
        return;
    };
    let row = &catalog.rows[index];
    lines.push(format!(
        "{}{}",
        row.label,
        if row.active {
            " · active"
        } else {
            " · inactive"
        }
    ));
    if let Some(baseline) = &state.baseline {
        lines.push(format!("Baseline: {}", catalog.label(baseline)));
    }
    lines.extend(row.details.clone());
    lines.push("Inspect and compare preserve the active context. Activation and restore are explicit local writes.".into());
}

fn append_read(lines: &mut Vec<String>, state: &ContextHistoryState) {
    let Some(data) = state.data.as_deref() else {
        lines.push("Reading the exact saved document…".into());
        return;
    };
    lines.push(
        data.pointer("/sourceState/message")
            .and_then(Value::as_str)
            .unwrap_or("Current-source applicability was not assessed.")
            .into(),
    );
    if data.pointer("/lessonState/usable").and_then(Value::as_bool) == Some(false) {
        lines.push(format!(
            "Lesson context needs review: {}",
            data.pointer("/lessonState/reason")
                .and_then(Value::as_str)
                .unwrap_or("origin unavailable")
        ));
    }
    lines.extend(crate::ui_view_models::context_goal::context_goal_lines(
        &data["goalState"],
    ));
    append_document(lines, data, state.document_raw);
}

fn append_document(lines: &mut Vec<String>, data: &Value, raw: bool) {
    if raw {
        lines.push("COMPLETE DOCUMENT · Tab summary".into());
        lines.extend(pretty_lines(&data["document"]));
    } else {
        lines.push("CONTEXT SUMMARY · Tab complete document".into());
        lines.extend(crate::ui_view_models::study_context::context_summary(
            &data["document"],
        ));
    }
}

fn append_comparison(lines: &mut Vec<String>, data: Option<&Value>) {
    let Some(data) = data else {
        lines.push("Comparing exact saved revisions…".into());
        return;
    };
    if let Some(changes) = data["contextText"].as_array() {
        for change in changes {
            append_text_change(lines, change);
        }
        if changes.is_empty() {
            lines
                .push("No editable text differs. Other document sections may have changed.".into());
        }
    }
    lines.extend([String::new(), "STRUCTURE AND COMPARISON COVERAGE".into()]);
    lines.extend(pretty_lines(&structural_comparison(data)));
}

/// The comparison minus its editable-text changes, which render above.
fn structural_comparison(data: &Value) -> Value {
    let mut structural = data.clone();
    if let Some(object) = structural.as_object_mut() {
        object.remove("contextText");
    }
    structural
}

fn append_text_change(lines: &mut Vec<String>, change: &Value) {
    lines.extend([
        String::new(),
        change["label"].as_str().unwrap_or("Changed text").into(),
        "Before:".into(),
    ]);
    lines.extend(
        change["before"]
            .as_str()
            .unwrap_or("")
            .lines()
            .map(|line| format!("- {line}")),
    );
    lines.push("After:".into());
    lines.extend(
        change["after"]
            .as_str()
            .unwrap_or("")
            .lines()
            .map(|line| format!("+ {line}")),
    );
}

fn pretty_lines(value: &Value) -> Vec<String> {
    serde_json::to_string_pretty(value)
        .unwrap_or_else(|error| format!("Cannot display saved data: {error}"))
        .lines()
        .map(str::to_string)
        .collect()
}
