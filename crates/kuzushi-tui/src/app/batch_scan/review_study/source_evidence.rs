use super::*;

impl ShellApp {
    pub(super) fn toggle_review_source_evidence(&mut self) {
        let Some(config) = self.router.campaign_mut().batch_scan_config.as_mut() else {
            return;
        };
        let Some(review) = config.review_plan.as_mut() else {
            return;
        };
        let next = if review.input["sourceEvidence"] == "cited" {
            "none"
        } else {
            "cited"
        };
        if let Some(message) = source_policy_blocker(&review.input, next) {
            config.notice = Some(message.into());
            return;
        }
        review.input["sourceEvidence"] = json!(next);
        reset_source_selection(&mut review.input, next);
        review.scroll = 0;
        config.study.invalidate_plan();
        config.notice = Some(format!("Source input changed explicitly. {} Enter freezes the new draft; v reads text and omissions before approval. Prior attempts and spending remain recorded.",
            if next == "none" { "Supporting-file choices cleared." } else { "f chooses supporting files." }));
    }
}

fn reset_source_selection(input: &mut Value, policy: &str) {
    let Some(input) = input.as_object_mut() else {
        return;
    };
    input.remove("sourceEvidenceRef");
    if policy == "none" {
        input.remove("sourceEvidenceFiles");
    }
}

fn source_policy_blocker(input: &Value, next: &str) -> Option<&'static str> {
    (next == "cited" && input["strategy"] != "standard").then_some(
        "Cited-file input is for standard Review. Use s to choose standard, or keep the selected deep strategy and its declared source tools. No plan or spending changed.")
}
