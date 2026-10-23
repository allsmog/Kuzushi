//! Failed preparation settles view state even when no worker was created.
use super::*;
use std::path::Path;

pub(super) fn tool_preparation_error_detail(error: &anyhow::Error) -> String {
    let mut detail = String::new();
    for cause in error.chain() {
        let text = cause.to_string();
        if includes_terminal_cause(&detail, &text) {
            continue;
        }
        if !detail.is_empty() {
            detail.push_str(": ");
        }
        detail.push_str(&text);
    }
    detail
}

fn includes_terminal_cause(detail: &str, cause: &str) -> bool {
    detail == cause || detail.ends_with(&format!(": {cause}"))
}

impl ShellApp {
    pub(super) fn report_tool_preparation_refusal(
        &mut self,
        tool: &str,
        target: Option<&Path>,
        message: String,
    ) {
        if self.target() == target {
            self.notify_tool_operation_failed(tool, &message);
        }
        self.log("error", message);
    }

    pub(super) fn notify_tool_operation_failed(&mut self, tool: &str, message: &str) {
        self.notify_tool_reader_failure(tool, message);
        self.context_baseline_allowance_failed(tool, message);
        self.study_preparation_failed(tool, message);
    }

    pub(super) fn notify_tool_reader_failure(&mut self, tool: &str, message: &str) {
        self.scope_review_failed(tool, message);
        self.context_edit_save_failed(tool, message);
        self.brief_save_failed(tool, message);
        self.context_check_failed(tool, message);
        self.context_comparison_failed(tool, message);
        self.context_history_failed(tool, message);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preparation_detail_retains_distinct_causes_without_repeating_embedded_causes() {
        let nested = anyhow::anyhow!("ignore policy hides scope.toml")
            .context("Workspace refused: ignore policy hides scope.toml");
        assert_eq!(
            tool_preparation_error_detail(&nested),
            "Workspace refused: ignore policy hides scope.toml"
        );
        let opaque =
            anyhow::anyhow!("ignore policy hides scope.toml").context("Cannot prepare workspace");
        assert_eq!(
            tool_preparation_error_detail(&opaque),
            "Cannot prepare workspace: ignore policy hides scope.toml"
        );
        let suffix = anyhow::anyhow!("scope.toml").context("Cannot open other_scope.toml");
        assert_eq!(
            tool_preparation_error_detail(&suffix),
            "Cannot open other_scope.toml: scope.toml"
        );
    }
}
