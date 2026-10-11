use super::*;

pub(super) fn tool() -> ToolDescriptor {
    tool_with_options("campaign:brief", "Read or save an immutable revision of operator goals, priorities and open questions. Changes no findings, model context, work or allowance.", vec![
        opt("mode", OptionType::Enum, "Read the current or exact revision, or save reviewed text.").choices(&["read","save"]).default(json!("read")),
        opt("briefId", OptionType::String, "Target-local brief identifier.").default(json!("repository")),
        opt("briefRef", OptionType::Json, "Exact immutable brief revision to read. Overrides briefId in read mode."),
        opt("expectedRevision", OptionType::Int, "Required for save: current revision, zero for a new brief.").integer_range(0, i64::from(u32::MAX)),
        opt("text", OptionType::String, "Reviewed goal, priorities and questions, up to 8192 UTF-8 bytes. Required for save."),
    ]).with_policy(workspace_policy(ToolPhase::Operate, RuntimeRequirement::Never, FindingStoreRequirement::Optional)).without_phase_result()
}
