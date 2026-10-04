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
            "Model: {model}\nTotal provider calls: {}\nProtected review calls: {}\nIncludes internal turns and retries. Existing commitments remain.\nDollar ceiling: not enforced; charges may be unavailable.\nReason: {}\n\n{}",
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
