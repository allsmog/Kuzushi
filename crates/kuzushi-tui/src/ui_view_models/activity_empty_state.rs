#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ActivityEmptyStateModel {
    pub(crate) title: &'static str,
    pub(crate) body: &'static str,
}

pub(crate) fn activity_empty_state_model() -> ActivityEmptyStateModel {
    ActivityEmptyStateModel {
        title: "ACTIVITY",
        body:
            "(no run active; start one with `scan` or `run <tool>` and the feed will appear here)",
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
                title: "ACTIVITY",
                body: "(no run active; start one with `scan` or `run <tool>` and the feed will appear here)",
            }
        );
    }
}
