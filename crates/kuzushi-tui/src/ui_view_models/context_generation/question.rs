use super::*;

pub(super) fn summary(
    config: &BatchScanConfig,
    generation: &StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    let mut lines = vec![generation.action(config).into(), "One question job · one worker · one attempt".into(),
        "Uses the selected context and captured operator notes, with tools disabled. No source execution, discovery, finding verdict or context edit.".into(),
        "Preparing, approving and starting work are separate actions. Reading a saved answer starts no request.".into(),
        format!("Context: {}",generation.context_input.pointer("/threatModelRef/revisionId").and_then(serde_json::Value::as_str).unwrap_or("select explicitly")),
        "QUESTION".into(), generation.context_input["question"].as_str().unwrap_or("question missing").into(),
        "G edits this question before its plan is frozen. Tab shows supplied options and input limits.".into(),
        format!("Total calls: {}", limit(config.study.max_provider_calls)),
        format!("Protected Review: {}", limit(config.study.protected_review_calls)),
        "Retries share the allowance. Dollar consumption is unknown; no dollar ceiling is enforced.".into()];
    lines.extend(config.notice.iter().cloned());
    lines.extend(generation_plan_lines(config));
    lines.extend(allowance_status_lines(config));
    lines
        .into_iter()
        .flat_map(|line| wrap_text(&line, width.max(1)))
        .collect()
}

pub(super) fn receipt_lines(
    receipt: &kuzushi_core::capabilities::campaign::ContextStudyReceipt,
) -> Vec<String> {
    vec![format!("Model: {}",crate::app::display_model_selector(&receipt.model)),
        format!("Source: {}",receipt.source_identity),format!("Plan: {}",receipt.campaign_id),
        format!("Plan digest: {}",receipt.plan_sha256),
        format!("Frozen context: {}",receipt.input.pointer("/threatModelRef/revisionId").and_then(serde_json::Value::as_str).unwrap_or("missing")),
        format!("Context limit: {} B · requested output: {} tokens",receipt.input["maxContextBytes"],receipt.input["maxOutputTokens"]),
        "Question and context cannot change after approval. n prepares a separately approved question.".into()]
}

/// The answer view in three parts so a renderer can draw the model's Markdown
/// body as formatted text while the receipt around it stays plain.
pub(crate) struct AnswerSections {
    pub(crate) head: Vec<String>,
    pub(crate) markdown: Option<String>,
    pub(crate) tail: Vec<String>,
}

pub(crate) fn answer_sections(generation: &crate::app::StudyContextGeneration) -> AnswerSections {
    let Some(answer) = &generation.generated_answer else {
        return AnswerSections {
            head: vec!["Question answer is unavailable; inspect its run receipt.".into()],
            markdown: None,
            tail: Vec::new(),
        };
    };
    let status = if answer.partial {
        "Partial model answer"
    } else {
        "Model answer"
    };
    AnswerSections {
        head: vec![
            status.into(),
            "QUESTION".into(),
            answer.question.clone(),
            "ANSWER".into(),
        ],
        markdown: Some(answer.answer.clone()),
        tail: vec![
            "This answer changes no context or finding decision.".into(),
            "CONTEXT AND RUN".into(),
            format!("Context: {}", answer.context_ref.revision_id),
            format!("Source: {}", answer.source_identity),
            format!(
                "Model: {}",
                crate::app::display_model_selector(&answer.model)
            ),
            format!("Run: {}", answer.run_id),
            "Esc returns to the plan · PgUp/PgDn reads · n needs a new approved question".into(),
        ],
    }
}

pub(super) fn answer_lines(
    generation: &crate::app::StudyContextGeneration,
    width: usize,
) -> Vec<String> {
    let sections = answer_sections(generation);
    sections
        .head
        .into_iter()
        .chain(sections.markdown)
        .chain(sections.tail)
        .flat_map(|line| {
            line.lines()
                .flat_map(|part| wrap_text(part, width.max(1)))
                .collect::<Vec<_>>()
        })
        .collect()
}
