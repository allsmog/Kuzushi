use super::*;
use crate::ui_view_models::context_goal::context_goal_lines;

pub(super) fn lines(document: &InvestigationReportDocument) -> Vec<String> {
    match document {
        InvestigationReportDocument::Study(receipt) => {
            context_goal_lines(&receipt.scope["contextGuidance"])
        }
        InvestigationReportDocument::ScopeStudy(receipt) => receipt
            .cases
            .iter()
            .flat_map(|case| named_lines(&case.label, &receipt.scope[&case.id]["contextGuidance"]))
            .collect(),
        InvestigationReportDocument::ContextMatrix(receipt) => receipt
            .cases
            .iter()
            .flat_map(|case| {
                named_lines(&case.label, &receipt.scope["caseContextGuidance"][&case.id])
            })
            .collect(),
    }
}

fn named_lines(label: &str, state: &serde_json::Value) -> Vec<String> {
    let mut lines = context_goal_lines(state);
    if !lines.is_empty() {
        lines.insert(0, format!("Context goal for {label}:"));
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn case_receipts_keep_separate_labels_and_do_not_assign_baseline_guidance_to_omitted_context() {
        let old = json!({"status":"recorded","reference":{"briefId":"repository","revision":1},"textBytes":13,"text":"Baseline goal"});
        let changed = json!({"status":"recorded","reference":{"briefId":"repository","revision":2},"textBytes":15,"text":"Experiment goal"});
        let omitted =
            json!({"status":"omitted","message":"Threat-model context was explicitly omitted."});
        let first = named_lines("Baseline", &old).join("\n");
        let second = named_lines("Experiment", &changed).join("\n");
        let none = named_lines("No context", &omitted).join("\n");
        assert!(first.contains("Context goal for Baseline:") && first.contains("Baseline goal"));
        assert!(
            second.contains("Context goal for Experiment:") && second.contains("exact revision 2")
        );
        assert!(!second.contains("Baseline goal"));
        assert!(none.contains("No context") && none.contains("context explicitly omitted"));
        assert!(!none.contains("Baseline goal") && !none.contains("unavailable"));
        assert!(named_lines("Legacy", &json!({})).is_empty());
    }
}
