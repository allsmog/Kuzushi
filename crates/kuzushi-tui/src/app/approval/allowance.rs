use super::*;

pub(super) fn confirmation(input: &serde_json::Value) -> PendingConfirm {
    let id = input["investigationId"]
        .as_str()
        .unwrap_or("missing investigation");
    let model = input["model"].as_str().unwrap_or("missing model");
    let current = input["expectedRevision"].as_u64().unwrap_or(0);
    PendingConfirm {
        kind: if input.get("campaignId").is_some() { ConfirmKind::InvestigationWork } else { ConfirmKind::InvestigationAllowance },
        tool: "campaign:approve-allowance".into(),
        target: format!("{id} · revision {current} → {}", current + 1),
        rationale: Some(format!(
            "SPENDING LIMITS\nShared allowance model: {model}\nFrozen work lists its execution model separately.\nTotal provider calls: {}\nProtected review calls: {}\nIncludes internal turns and retries. Existing commitments remain.\nDollar ceiling: not enforced; charges may be unavailable.\nReason: {}\n\n{}",
            input["maxProviderCalls"], input["protectedReviewCalls"],
            input["reason"].as_str().unwrap_or("not provided"),
            work_terms(input),
        )),
        actor: None, allowlist: None, remembered: false,
    }
}

fn work_terms(input: &serde_json::Value) -> String {
    let Some(campaign) = input["campaignId"].as_str() else {
        return "Approves this allowance only; starts no jobs.".into();
    };
    format!("Campaign: {campaign} · {} fixed jobs · {} attempt(s) each\nPlan digest: {}\nFailure and cancellation consume attempts. No automatic extra work.\nApproves this plan and allowance; starts no jobs.",
        input["campaignJobs"], input["maxJobAttempts"], input["campaignPlanSha256"].as_str().unwrap_or("missing"))
}

pub(crate) fn with_accounting_terms(
    app: &ShellApp,
    input: &serde_json::Value,
    mut confirm: PendingConfirm,
) -> PendingConfirm {
    let work = work_summary(app, input, confirm.kind);
    let sections = [
        work.as_ref()
            .map(|summary| summary.overview.join("\n"))
            .unwrap_or_default(),
        accounting_terms(app, input),
        confirm
            .rationale
            .take()
            .unwrap_or_else(|| "Terms unavailable".into()),
        resource_terms(app, input),
        work.map(|summary| work_details(summary.details))
            .unwrap_or_default(),
    ];
    confirm.rationale = Some(
        sections
            .into_iter()
            .filter(|section| !section.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n"),
    );
    confirm
}

fn work_summary(
    app: &ShellApp,
    input: &serde_json::Value,
    kind: ConfirmKind,
) -> Option<crate::ui_view_models::AllowanceWorkSummary> {
    if kind != ConfirmKind::InvestigationWork {
        return None;
    }
    crate::ui_view_models::allowance_work_summary(app, input)
}

fn work_details(lines: Vec<String>) -> String {
    if lines.is_empty() {
        return String::new();
    }
    format!("PLAN DETAILS\n{}", lines.join("\n"))
}

fn accounting_terms(app: &ShellApp, input: &serde_json::Value) -> String {
    let Some(snapshot) = revised_snapshot(app, input) else {
        return String::new();
    };
    format!("CURRENT ACCOUNTING\nCalls already committed: {} · unresolved: {}.\nAvailable under these limits: {} context/scan calls · {} protected review calls.\nAll fixed jobs share these calls, including internal turns and retries.\nAt the limit, unfinished jobs remain partial. Finish and report or revise work explicitly.",
        snapshot.committed_calls, snapshot.unresolved_calls, snapshot.remaining_discovery_calls(), snapshot.protected_review_remaining())
}

fn resource_terms(app: &ShellApp, input: &serde_json::Value) -> String {
    let Some(config) = app.router.campaign().batch_scan_config.as_ref() else {
        return String::new();
    };
    let Some((campaign_id, plan_sha256, _)) = config.study.plan_identity() else {
        return String::new();
    };
    if input["campaignId"].as_str() != Some(campaign_id)
        || input["campaignPlanSha256"].as_str() != Some(plan_sha256)
    {
        return String::new();
    }
    let mut projection = config.clone();
    projection.study.max_provider_calls = input["maxProviderCalls"]
        .as_u64()
        .and_then(|count| count.try_into().ok());
    projection.study.protected_review_calls = input["protectedReviewCalls"]
        .as_u64()
        .and_then(|count| count.try_into().ok());
    projection.study.max_job_attempts = input["maxJobAttempts"]
        .as_u64()
        .and_then(|count| count.try_into().ok())
        .unwrap_or(0);
    let lines = crate::ui_view_models::study_config::study_resource_lines(&projection);
    format!("RESOURCE ESTIMATE\n{}", lines.join("\n"))
}

fn revised_snapshot(
    app: &ShellApp,
    input: &serde_json::Value,
) -> Option<kuzushi_core::allowance::AllowanceSnapshot> {
    if input["campaignId"].as_str().is_none() {
        return None;
    }
    let study = &app.router.campaign().batch_scan_config.as_ref()?.study;
    let mut snapshot = study.allowance.clone()?;
    if study.accounting_error.is_some() {
        return None;
    }
    if input["investigationId"].as_str()? != snapshot.investigation_id
        || input["expectedRevision"].as_u64()? != u64::from(snapshot.revision)
    {
        return None;
    }
    snapshot.limits = kuzushi_core::allowance::AllowanceLimits {
        max_provider_calls: input["maxProviderCalls"].as_u64()?.try_into().ok()?,
        protected_review_calls: input["protectedReviewCalls"].as_u64()?.try_into().ok()?,
    };
    Some(snapshot)
}

/// Approval is available at the end of the same document the operator sees.
/// The viewport never hides terms behind an enabled generic confirmation.
pub(crate) fn approval_visible(app: &ShellApp) -> bool {
    let viewport = app.viewport();
    crate::ui_view_models::allowance_review_model(app, viewport.columns, viewport.rows)
        .is_none_or(|review| review.allows_approval())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::modules::ModuleRegistry;
    use serde_json::json;

    const TEST_MODEL: &str = "openai-codex:gpt-5.5";
    mod hierarchy;

    fn app_with_commitments(root: &std::path::Path) -> ShellApp {
        let mut app = ShellApp::new(Default::default(), None);
        let mut config = crate::app::batch_scan::BatchScanConfig::load(root, None);
        config.study.allowance = Some(kuzushi_core::allowance::AllowanceSnapshot {
            schema_version: 1,
            investigation_id: "study".into(),
            revision: 2,
            model: TEST_MODEL.into(),
            limits: kuzushi_core::allowance::AllowanceLimits {
                max_provider_calls: 10,
                protected_review_calls: 3,
            },
            committed_calls: 1,
            review_calls: 0,
            unresolved_calls: 1,
            cost: kuzushi_core::runtime::RuntimeCostReport::UNAVAILABLE,
            work_plan: None,
        });
        app.router.campaign_mut().batch_scan_config = Some(config);
        app
    }

    #[test]
    fn revised_work_approval_discloses_net_calls_without_resetting_commitments() {
        let root = tempfile::tempdir().unwrap();
        let app = app_with_commitments(root.path());
        let input = json!({"campaignId":"three-pass","investigationId":"study","expectedRevision":2,
            "maxProviderCalls":5,"protectedReviewCalls":2});
        let confirm = with_accounting_terms(&app, &input, confirmation(&input));
        let text = confirm.rationale.unwrap();
        assert!(text.contains("Calls already committed: 1 · unresolved: 1"));
        assert!(text.contains("2 context/scan calls · 2 protected review calls"));
        assert!(text.contains("unfinished jobs remain partial"));
        assert_eq!(
            app.router
                .campaign()
                .batch_scan_config
                .as_ref()
                .unwrap()
                .study
                .allowance
                .as_ref()
                .unwrap()
                .limits
                .max_provider_calls,
            10
        );
    }

    #[test]
    fn approval_never_borrows_accounting_from_a_different_revision_or_investigation() {
        let root = tempfile::tempdir().unwrap();
        let mut app = app_with_commitments(root.path());
        let base = json!({"campaignId":"three-pass","investigationId":"study","expectedRevision":2,
            "maxProviderCalls":5,"protectedReviewCalls":2});
        for (key, value) in [
            ("expectedRevision", json!(1)),
            ("investigationId", json!("other")),
        ] {
            let mut input = base.clone();
            input[key] = value;
            assert!(revised_snapshot(&app, &input).is_none());
        }
        app.router
            .campaign_mut()
            .batch_scan_config
            .as_mut()
            .unwrap()
            .study
            .accounting_error = Some("unreadable".into());
        assert!(revised_snapshot(&app, &base).is_none());
    }

    #[test]
    fn finite_work_confirmation_names_exact_plan_terms() {
        let input = json!({"investigationId":"study","expectedRevision":0,"model":"openai-codex:gpt-5.5",
            "maxProviderCalls":9,"protectedReviewCalls":3,"campaignId":"finite","campaignJobs":3,
            "maxJobAttempts":1,"campaignPlanSha256":format!("sha256:{}", "a".repeat(64))});
        let confirm = confirmation(&input);
        assert_eq!(confirm.kind, ConfirmKind::InvestigationWork);
        assert!(!confirm.kind.allows_remembered_yes());
        let text = confirm.rationale.as_deref().unwrap();
        assert!(text.contains("3 fixed jobs · 1 attempt(s) each"));
        assert!(text.contains(&"a".repeat(64)));
    }

    #[test]
    fn allowance_confirmation_names_exact_terms_and_does_not_allow_remembered_approval() {
        let registry = ModuleRegistry::with_v2_builtins();
        let tool = registry.resolve_tool("campaign:approve-allowance").unwrap();
        let input = json!({"investigationId":"study","expectedRevision":2,"model":"openai-codex:gpt-5.5","maxProviderCalls":9,"protectedReviewCalls":3});
        let confirm = descriptor_approval_confirm(tool, &input).unwrap();
        assert_eq!(confirm.kind, ConfirmKind::InvestigationAllowance);
        assert_eq!(confirm.target, "study · revision 2 → 3");
        let rationale = confirm.rationale.as_deref().unwrap();
        for text in [
            "openai-codex:gpt-5.5",
            "Total provider calls: 9",
            "Protected review calls: 3",
            "not enforced",
            "starts no jobs",
        ] {
            assert!(rationale.contains(text));
        }
        assert!(!confirm.kind.allows_remembered_yes());
    }
}
