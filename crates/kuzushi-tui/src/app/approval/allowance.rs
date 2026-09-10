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
            "Model: {model}\nTotal provider calls: {} · protected review: {}\nIncludes internal turns and retries. Existing commitments remain.\nDollar ceiling: not enforced; charges may be unavailable.\n{}",
            input["maxProviderCalls"], input["protectedReviewCalls"],
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

/// The generic confirmation card cannot expose these terms on smaller screens.
/// Keep cancellation available until the dedicated paged allowance editor lands.
pub(crate) fn approval_visible(app: &ShellApp) -> bool {
    let Some(confirm) = app.advisory().pending_confirm.as_ref() else {
        return true;
    };
    let Some((columns, rows)) = minimum_viewport(confirm.kind) else {
        return true;
    };
    let viewport = app.viewport();
    viewport.columns >= columns && viewport.rows >= rows
}

pub(crate) fn minimum_viewport(kind: ConfirmKind) -> Option<(u16, u16)> {
    match kind {
        ConfirmKind::InvestigationWork => Some((120, 36)),
        ConfirmKind::InvestigationAllowance => Some((80, 24)),
        _ => None,
    }
}

pub(crate) fn resize_hint(viewport: Option<(u16, u16)>) -> String {
    let (columns, rows) = viewport.unwrap_or((80, 24));
    format!("resize to {columns}×{rows} · Esc cancel")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kuzushi_core::{modules::ModuleRegistry, V2Config};
    use serde_json::json;

    #[test]
    fn finite_work_confirmation_requires_room_for_the_entire_plan_receipt() {
        let input = json!({"investigationId":"study","expectedRevision":0,"model":"openai-codex:gpt-5.5",
            "maxProviderCalls":9,"protectedReviewCalls":3,"campaignId":"finite","campaignJobs":3,
            "maxJobAttempts":1,"campaignPlanSha256":format!("sha256:{}", "a".repeat(64))});
        let confirm = confirmation(&input);
        assert_eq!(confirm.kind, ConfirmKind::InvestigationWork);
        assert!(!confirm.kind.allows_remembered_yes());
        let text = confirm.rationale.as_deref().unwrap();
        assert!(text.contains("3 fixed jobs · 1 attempt(s) each"));
        assert!(text.contains(&"a".repeat(64)));
        for (columns, rows) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_viewport(TerminalViewport { columns, rows });
            app.advisory_mut().pending_confirm = Some(confirm.clone());
            let visible = columns >= 120 && rows >= 36;
            assert_eq!(approval_visible(&app), visible);
            assert_eq!(app.resolve_confirm(true, false).is_some(), visible);
            if !visible {
                assert!(app.resolve_confirm(false, false).is_some());
            }
        }
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
            "protected review: 3",
            "not enforced",
            "starts no jobs",
        ] {
            assert!(rationale.contains(text));
        }
        assert!(!confirm.kind.allows_remembered_yes());
        for (columns, rows) in [(40, 12), (60, 20), (80, 24), (96, 89), (120, 36), (160, 48)] {
            let mut app = ShellApp::new(V2Config::default(), None);
            app.set_viewport(TerminalViewport { columns, rows });
            app.advisory_mut().pending_confirm = Some(confirm.clone());
            let visible = columns >= 80 && rows >= 24;
            assert_eq!(approval_visible(&app), visible);
            assert_eq!(app.resolve_confirm(true, false).is_some(), visible);
            if !visible {
                assert!(app.advisory().pending_confirm.is_some());
                let card = crate::ui_view_models::confirm_card_model(&app).unwrap();
                assert!(!card.allows_decision);
                assert!(app.resolve_confirm(false, false).is_some());
            }
        }
    }
}
