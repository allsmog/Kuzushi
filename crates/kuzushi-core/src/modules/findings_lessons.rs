//! Explicit operator review of reusable context. Lesson drafts never alter findings.
use super::*;
use crate::findings::{FindingLesson, LessonContent, LessonRef, LessonState};

pub(crate) fn lesson_tools() -> Vec<ToolDescriptor> {
    vec![
        lesson_tool("findings:lessons","Inspect saved lesson revisions and their original human confirmation.",vec![
            opt("limit",OptionType::Int,"Lessons per page, 1 to 200.").integer_range(1,200).default(json!(50)),
            opt("offset",OptionType::Int,"Lesson page offset.").integer_range(0,1_000_000).default(json!(0)),
            opt("lessonRef",OptionType::Json,"Exact lesson revision to inspect instead of a page."),
        ],ToolEffect::Read),
        lesson_tool("findings:lesson-save","Save a reusable lesson draft from an explicitly confirmed finding, or edit an exact lesson revision. Edits require new review.",vec![
            opt("findingId",OptionType::Int,"Exact durable finding generation for a new draft.").integer_range(1,i64::MAX),
            opt("lessonRef",OptionType::Json,"Exact saved lesson reference when editing an existing draft."),
            opt("content",OptionType::Json,"Lesson title, text, applicability and limitations. All four are required.").required(),
        ],ToolEffect::WorkspaceWrite),
        lesson_tool("findings:lesson-review","Accept, reject or retire an exact lesson revision with an operator reason. Selection into future context remains separate.",vec![
            opt("lessonRef",OptionType::Json,"Exact lesson revision shown during review.").required(),
            opt("state",OptionType::Enum,"Operator lesson decision.").choices(&["accepted","rejected","retired"]).required(),
            opt("note",OptionType::String,"Required reason for the lesson decision.").required(),
        ],ToolEffect::WorkspaceWrite),
    ]
}

fn lesson_tool(
    name: &str,
    description: &str,
    options: Vec<OptionSpec>,
    effect: ToolEffect,
) -> ToolDescriptor {
    let mut tool = tool_with_options(name, description, options)
        .with_policy(tool_policy(
            ToolPhase::Review,
            RuntimeRequirement::Never,
            effect,
            WorkspaceRequirement::Required,
            FindingStoreRequirement::Required,
        ))
        .without_phase_result();
    if effect == ToolEffect::WorkspaceWrite {
        tool.approval = ApprovalPolicy::Explicit;
    }
    tool
}

pub(crate) fn generation_tool() -> ToolDescriptor {
    let mut tool=tool_with_options("findings:lesson-generate","Propose one defensive lesson draft from an exact human-confirmed observation. One bounded synthesis request; acceptance and context reuse remain separate.",vec![
        opt("findingId",OptionType::Int,"Exact human-confirmed finding generation.").integer_range(1,i64::MAX).required(),
        opt("originRef",OptionType::Json,"Frozen lesson origin, including exact confirmation and observation. Study preparation supplies it."),
        opt("guidance",OptionType::String,"Operator guidance, at most 2048 bytes.").default(json!("")),
        opt("maxSourceBytes",OptionType::Int,"Captured source bytes allowed in this request. Source outside this limit is explicitly omitted; current source is not substituted.").integer_range(1024,65536).default(json!(16384)),
        opt("maxOutputTokens",OptionType::Int,"Requested output tokens; transport may not enforce this ceiling. The approved provider-call limit remains enforced.").integer_range(256,4096).default(json!(1024)),
        opt("thinkingLevel",OptionType::Enum,"Reasoning effort; omit to inherit the selected runtime.").choices(&["low","medium","high","xhigh"]),
        model_option(),
        opt("allowanceRef",OptionType::Json,"Explicitly approved investigation revision and work item. Internal transport attempts share this allowance.").required(),
    ]).with_policy(workspace_policy(ToolPhase::Review,RuntimeRequirement::Always,FindingStoreRequirement::Required)).with_allowance_category(AllowanceCategory::Learning).without_phase_result();
    tool.approval = ApprovalPolicy::Explicit;
    tool
}

pub(in crate::modules) fn execute(
    name: &str,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let store = ctx
        .findings_store
        .context("Lessons require the findings store")?;
    match name {
        "findings:lessons" => read_lessons(store, input),
        "findings:lesson-save" => {
            ctx.ensure_active()?;
            save_lesson(store, input, ctx)
        }
        "findings:lesson-review" => {
            ctx.ensure_active()?;
            review_lesson(store, input)
        }
        _ => anyhow::bail!("Unknown lesson tool"),
    }
}

fn read_lessons(store: &FindingStore, input: &Value) -> Result<Value> {
    if let Some(reference) = input.get("lessonRef") {
        return lesson_result(
            store.finding_lesson_revision(&serde_json::from_value(reference.clone())?)?,
            "Saved lesson revision; inspect its origin before reuse",
        );
    }
    let page = store.finding_lessons(
        input["limit"].as_u64().unwrap_or(50) as usize,
        input["offset"].as_u64().unwrap_or(0) as usize,
    )?;
    let rows = page
        .rows
        .iter()
        .map(|record| Ok(json!({"lesson":record,"lessonRef":record.reference()?})))
        .collect::<Result<Vec<_>>>()?;
    Ok(
        json!({"ok":true,"output":format!("{} saved lessons. Drafts require review; accepted lessons require explicit context selection.",rows.len()),"data":{"rows":rows,"offset":page.offset,"hasMore":page.has_more}}),
    )
}

fn save_lesson(
    store: &FindingStore,
    input: &Value,
    ctx: &ToolExecutionContext<'_>,
) -> Result<Value> {
    let content: LessonContent =
        serde_json::from_value(input["content"].clone()).context("Invalid lesson fields")?;
    let record = match (input.get("findingId"), input.get("lessonRef")) {
        (Some(id), None) => {
            let target = ctx.workspace.context("Select a lesson target")?;
            let origin =
                store.lesson_origin(target.root(), id.as_i64().context("Invalid finding id")?)?;
            store.draft_finding_lesson(content, origin, None)?
        }
        (None, Some(reference)) => {
            store.revise_finding_lesson(&serde_json::from_value(reference.clone())?, content)?
        }
        _ => anyhow::bail!("Choose findingId for a new lesson or lessonRef for an edit"),
    };
    lesson_result(
        record,
        "Lesson draft saved. Review it before adding it to context.",
    )
}

fn review_lesson(store: &FindingStore, input: &Value) -> Result<Value> {
    let reference: LessonRef = serde_json::from_value(input["lessonRef"].clone())?;
    let state: LessonState = serde_json::from_value(input["state"].clone())?;
    let note = input["note"]
        .as_str()
        .context("Lesson review reason is required")?;
    let record = store.review_finding_lesson(&reference, state, note.trim().into())?;
    lesson_result(
        record,
        "Lesson decision saved. Future context selection remains explicit.",
    )
}

fn lesson_result(record: FindingLesson, output: &str) -> Result<Value> {
    Ok(json!({"ok":true,"output":output,"data":{"lessonRef":record.reference()?,"lesson":record}}))
}

#[cfg(test)]
mod tests;
