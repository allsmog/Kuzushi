//! A selected authenticated report supplies historical associations after restart.
use super::*;
use crate::app::ShellApp;
use crate::ui_view_models::report_summary::{report_document_view, ReportReadView};
use kuzushi_core::workspace::{InvestigationReportDocument, ScopeStudyInvestigationReceipt};

pub(super) fn detail(app: &ShellApp, state: &ScopeReviewState, id: &str) -> Option<Vec<String>> {
    app.scope_context_report_key()?;
    match report_document_view(app) {
        ReportReadView::Ready(document) => matching_detail(state, id, &document),
        ReportReadView::Empty => None,
        ReportReadView::Failed(error) => Some(vec![format!("Selected study context unavailable: {error}")]),
        _ => Some(vec!["Selected study context is loading. Previous context is not used as the current association.".into()]),
    }
}

fn matching_detail(
    state: &ScopeReviewState,
    id: &str,
    document: &InvestigationReportDocument,
) -> Option<Vec<String>> {
    let InvestigationReportDocument::ScopeStudy(receipt) = document else {
        return None;
    };
    if receipt.scope_proposal_ref != state.review.as_ref()?.reference {
        return None;
    }
    recorded_case(receipt, id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{
        ReportStudyRef, ScopeReviewState, ShellView, ViewHydrationResult, ViewHydrationValue,
    };

    #[test]
    fn loading_and_failed_reads_are_honest_without_substituting_context() {
        let root = tempfile::tempdir().unwrap();
        let mut app = ShellApp::new(kuzushi_core::V2Config::default(), None);
        app.set_target(Some(root.path().into()));
        app.set_shell_view(ShellView::Module);
        let state = ScopeReviewState::new(root.path().into());
        *app.router.scope_review_mut() = Some(state.clone());
        app.router.report_mut().set_study(Some(ReportStudyRef {
            campaign_id: "owned-study".into(),
            plan_sha256: "owned-digest".into(),
        }));
        assert!(detail(&app, &state, "scope")
            .unwrap()
            .join(" ")
            .contains("loading"));
        let key = app.report_hydration_key();
        app.workbench_cache()
            .borrow_mut()
            .apply_view_hydration(ViewHydrationResult {
                target: root.path().into(),
                key,
                value: ViewHydrationValue::InvestigationReport(Err("Owned invalid receipt".into())),
            });
        assert!(detail(&app, &state, "scope")
            .unwrap()
            .join(" ")
            .contains("unavailable: Owned invalid receipt"));
        app.router.scope_review_mut().as_mut().unwrap().open = false;
        assert!(detail(&app, &state, "scope").is_none());
    }
}

fn recorded_case(receipt: &ScopeStudyInvestigationReceipt, id: &str) -> Option<Vec<String>> {
    let selection = receipt
        .context_selections
        .iter()
        .find(|case| case.scope_id == id)?;
    let frozen = receipt.cases.iter().find(|case| case.id == id)?;
    let mut lines = vec![
        format!(
            "Context association: {}",
            super::super::scope_context::binding_label(selection)
        ),
        format!("Recorded study: {}", receipt.campaign_id),
    ];
    super::super::scope_context::append_reference(
        &mut lines,
        "Frozen common context",
        Some(&receipt.inherited_threat_model_ref),
    );
    super::super::scope_context::append_reference(
        &mut lines,
        "Context actually frozen for scans",
        Some(
            frozen
                .equivalence
                .components
                .threat_model
                .as_ref()
                .unwrap_or(&serde_json::Value::Null),
        ),
    );
    lines.push(format!(
        "Recorded plan: {}. New work needs its own approval.",
        receipt.plan_sha256
    ));
    Some(lines)
}
