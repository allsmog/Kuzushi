//! Display historical context limitations independently of completed scan work.
use super::*;
use serde_json::Value;

pub(super) fn lines(document: &InvestigationReportDocument, details: bool) -> Vec<String> {
    match document {
        InvestigationReportDocument::Study(receipt) => {
            state_lines(&receipt.scope["contextEvidence"], details)
        }
        InvestigationReportDocument::ScopeStudy(receipt) => case_lines(
            receipt.cases.iter().map(|case| {
                (
                    case.label.as_str(),
                    &receipt.scope[&case.id]["contextEvidence"],
                )
            }),
            details,
            "boundaries",
        ),
        InvestigationReportDocument::ContextMatrix(receipt) => case_lines(
            receipt.cases.iter().map(|case| {
                (
                    case.label.as_str(),
                    &receipt.scope["caseContextEvidence"][&case.id],
                )
            }),
            details,
            "context cases",
        ),
    }
}

fn case_lines<'a>(
    states: impl Iterator<Item = (&'a str, &'a Value)>,
    details: bool,
    noun: &str,
) -> Vec<String> {
    if details {
        return states
            .flat_map(|(label, state)| named_lines(label, state, true))
            .collect();
    }
    let mut groups = std::collections::BTreeMap::<Vec<String>, Vec<&str>>::new();
    for (label, state) in states {
        groups
            .entry(case_state_lines(state, false))
            .or_default()
            .push(label);
    }
    groups
        .into_iter()
        .flat_map(|(lines, labels)| group_lines(lines, &labels, noun))
        .collect()
}

fn group_lines(mut lines: Vec<String>, labels: &[&str], noun: &str) -> Vec<String> {
    if let Some(first) = lines.first_mut() {
        *first = if labels.len() == 1 {
            format!("{}: {first}", labels[0])
        } else {
            format!("{first} · {} {noun}", labels.len())
        };
    }
    lines
}

fn case_state_lines(state: &Value, details: bool) -> Vec<String> {
    let lines = state_lines(state, details);
    if lines.is_empty() {
        return vec!["Context evidence: not recorded.".into()];
    }
    lines
}

fn named_lines(label: &str, state: &Value, details: bool) -> Vec<String> {
    let mut lines = case_state_lines(state, details);
    if let Some(first) = lines.first_mut() {
        *first = format!("{label}: {first}");
    }
    lines
}

fn state_lines(state: &Value, details: bool) -> Vec<String> {
    match state["status"].as_str() {
        Some("recorded") => recorded_lines(state, details),
        Some("omitted") => vec!["Context: explicitly omitted.".into()],
        Some("unbound") => vec!["Context: no explicit historical reference recorded.".into()],
        Some("unavailable") => vec![
            "Context evidence: unavailable.".into(),
            state["message"]
                .as_str()
                .unwrap_or("Recorded context could not be read.")
                .into(),
        ],
        _ => Vec::new(),
    }
}

fn recorded_lines(state: &Value, details: bool) -> Vec<String> {
    let verification = &state["verification"];
    let verdict = verification["verdict"].as_str().unwrap_or("unrecorded");
    let mut lines = vec![format!("Context grounding: {verdict}.")];
    if !details {
        return lines;
    }
    if let Some(reason) = verification["groundingDegraded"].as_str() {
        lines.push(format!("Context limitation: {reason}"));
    }
    lines.extend(super::super::study_context::context_source_receipt_lines(
        &state["sourceContext"],
    ));
    lines
}

#[cfg(test)]
mod tests;
