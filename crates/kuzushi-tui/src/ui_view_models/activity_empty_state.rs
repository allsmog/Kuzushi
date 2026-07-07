#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityEmptyStateModel {
    pub(crate) title: &'static str,
    pub(crate) glyph_label: &'static str,
    pub(crate) explanations: &'static [&'static str],
    pub(crate) ctas: &'static [(&'static str, &'static str)],
}

pub(crate) fn activity_empty_state_model() -> ActivityEmptyStateModel {
    ActivityEmptyStateModel {
        title: "ACTIVITY · idle",
        glyph_label: "no active run",
        explanations: &[
            "live task status and agent action logs appear here during scans and runs.",
            "start work from this shell to keep control without leaving the TUI.",
        ],
        ctas: &[
            (
                "scan",
                "run the configured target through the scan pipeline",
            ),
            ("run <tool>", "launch one module and stream its output here"),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn activity_empty_state_model_projects_inactive_copy() {
        assert_eq!(
            activity_empty_state_model(),
            ActivityEmptyStateModel {
                title: "ACTIVITY · idle",
                glyph_label: "no active run",
                explanations: &[
                    "live task status and agent action logs appear here during scans and runs.",
                    "start work from this shell to keep control without leaving the TUI.",
                ],
                ctas: &[
                    (
                        "scan",
                        "run the configured target through the scan pipeline"
                    ),
                    ("run <tool>", "launch one module and stream its output here"),
                ],
            }
        );
    }
}
