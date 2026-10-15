use kuzushi_core::run_lifecycle::{RunItemStatus, RunPresentationPayloadV1, RunPresentationV1};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReplayIssueModel {
    pub(crate) label: &'static str,
    pub(crate) message: String,
    pub(crate) tool: Option<String>,
}

/// Promote a recorded issue for an incomplete run. The full typed receipt stays
/// intact; a tool error is not inferred to be the cause of an aggregate outcome.
pub(super) fn replay_issue(presentation: &RunPresentationV1) -> Option<ReplayIssueModel> {
    if !needs_attention(presentation.terminal_status) {
        return None;
    }
    let mut cells = presentation
        .summary
        .iter()
        .flat_map(|section| &section.cells)
        .rev();
    let issue = cells
        .clone()
        .find_map(|cell| issue_from_payload(&cell.payload));
    if issue.is_some() || presentation.terminal_status != Some(RunItemStatus::Partial) {
        return issue;
    }
    cells.find_map(|cell| warning_from_payload(&cell.payload))
}

fn warning_from_payload(payload: &RunPresentationPayloadV1) -> Option<ReplayIssueModel> {
    let RunPresentationPayloadV1::ResultSummary(result) = payload else {
        return None;
    };
    result
        .warnings
        .iter()
        .find(|warning| !warning.as_str().trim().is_empty())
        .map(|warning| ReplayIssueModel {
            label: "Recorded warning",
            message: warning.to_string(),
            tool: Some(kuzushi_core::modules::tool_display_name(
                result.tool.as_str(),
            )),
        })
}

fn needs_attention(status: Option<RunItemStatus>) -> bool {
    matches!(
        status,
        Some(
            RunItemStatus::Failed
                | RunItemStatus::Blocked
                | RunItemStatus::Partial
                | RunItemStatus::Canceled
                | RunItemStatus::Interrupted
        )
    )
}

fn issue_from_payload(payload: &RunPresentationPayloadV1) -> Option<ReplayIssueModel> {
    match payload {
        RunPresentationPayloadV1::ResultSummary(result) => result
            .errors
            .iter()
            .find(|error| !error.as_str().trim().is_empty())
            .map(|error| ReplayIssueModel {
                label: "Recorded error",
                message: error.to_string(),
                tool: Some(kuzushi_core::modules::tool_display_name(
                    result.tool.as_str(),
                )),
            }),
        RunPresentationPayloadV1::ResultHydrationIssue(issue) => Some(ReplayIssueModel {
            label: "Evidence unavailable",
            message: issue.detail.to_string(),
            tool: None,
        }),
        _ => None,
    }
}

#[cfg(test)]
mod tests;
