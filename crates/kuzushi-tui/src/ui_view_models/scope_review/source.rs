use crate::app::{ScopeReviewState, ShellApp};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ScopeRevisionStatus {
    NoInventory,
    Checking,
    Unavailable,
    Different,
    Modified,
    Matches,
}

pub(crate) struct ScopeSourceView {
    pub status: ScopeRevisionStatus,
    pub observed_revision: Option<String>,
}

pub(crate) fn scope_source_view(app: &ShellApp, state: &ScopeReviewState) -> ScopeSourceView {
    let facts = app
        .active_target_facts()
        .filter(|facts| facts.path == state.target);
    let observed = facts.and_then(|facts| facts.revision.as_deref());
    let recorded = state
        .review
        .as_ref()
        .and_then(|review| review.record.source.git_revision.as_deref());
    ScopeSourceView {
        status: if state.review.is_none() {
            ScopeRevisionStatus::NoInventory
        } else {
            revision_status(
                recorded,
                observed,
                facts.and_then(|facts| facts.dirty),
                app.active_target_facts_loading(),
            )
        },
        observed_revision: observed.map(str::to_owned),
    }
}

fn revision_status(
    recorded: Option<&str>,
    observed: Option<&str>,
    dirty: Option<bool>,
    loading: bool,
) -> ScopeRevisionStatus {
    if loading {
        return ScopeRevisionStatus::Checking;
    }
    let Some(observed) = observed else {
        return ScopeRevisionStatus::Unavailable;
    };
    if recorded != Some(observed) {
        return ScopeRevisionStatus::Different;
    }
    matched_revision(dirty)
}

fn matched_revision(dirty: Option<bool>) -> ScopeRevisionStatus {
    match dirty {
        Some(true) => ScopeRevisionStatus::Modified,
        Some(false) => ScopeRevisionStatus::Matches,
        None => ScopeRevisionStatus::Unavailable,
    }
}

impl ScopeSourceView {
    pub fn differs(&self) -> bool {
        self.status == ScopeRevisionStatus::Different
    }

    pub fn label(&self) -> &'static str {
        match self.status {
            ScopeRevisionStatus::Different => "Last observed SHA differs",
            ScopeRevisionStatus::Modified => "Last check: working tree modified",
            ScopeRevisionStatus::Matches => "Last SHA matches; files unchecked",
            state => unchecked_label(state),
        }
    }

    pub fn details(&self) -> Vec<String> {
        vec![
            format!("Source comparison: {}.", self.label()),
            format!("Last observed Git SHA: {}", self.observed_revision.as_deref().unwrap_or("unavailable")),
            "Git revision comparison leaves file content unchecked. Preparation and execution recheck source. In scope navigation, r reloads the saved scope and repository facts without starting scans or model requests.".into(),
        ]
    }
}

fn unchecked_label(state: ScopeRevisionStatus) -> &'static str {
    match state {
        ScopeRevisionStatus::NoInventory => "Build inventory to bind source",
        ScopeRevisionStatus::Checking => "Reading repository facts",
        _ => "Source unchecked; facts incomplete",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_sha_never_claims_matching_contents() {
        assert_eq!(
            revision_status(Some("same"), Some("same"), Some(false), false),
            ScopeRevisionStatus::Matches
        );
        assert!(ScopeSourceView {
            status: ScopeRevisionStatus::Matches,
            observed_revision: Some("same".into())
        }
        .label()
        .contains("files unchecked"));
        assert_eq!(
            revision_status(Some("same"), Some("same"), Some(true), false),
            ScopeRevisionStatus::Modified
        );
    }

    #[test]
    fn missing_or_pending_facts_cannot_claim_a_match() {
        assert_eq!(
            revision_status(Some("old"), Some("new"), Some(false), true),
            ScopeRevisionStatus::Checking
        );
        assert_eq!(
            revision_status(None, None, None, false),
            ScopeRevisionStatus::Unavailable
        );
        assert_eq!(
            revision_status(Some("old"), None, Some(false), false),
            ScopeRevisionStatus::Unavailable
        );
        assert_eq!(
            revision_status(Some("same"), Some("same"), None, false),
            ScopeRevisionStatus::Unavailable
        );
    }

    #[test]
    fn revision_comparison_uses_full_sha_and_detects_new_git_identity() {
        assert_eq!(
            revision_status(
                Some("1234567890-old"),
                Some("1234567890-new"),
                Some(false),
                false
            ),
            ScopeRevisionStatus::Different
        );
        assert_eq!(
            revision_status(None, Some("new"), Some(false), false),
            ScopeRevisionStatus::Different
        );
    }
}
