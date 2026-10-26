use super::*;

pub(in crate::modules) fn declare_allowance_option(mut tool: ToolDescriptor) -> ToolDescriptor {
    if supports_allowance(&tool) && !tool.options.iter().any(|option| option.name == OPTION) {
        tool.options.push(
            opt(
                OPTION,
                OptionType::Json,
                "Approved call allowance reference: schemaVersion=1, investigationId, revision and workId. Does not approve or start extra work. Dollar cost may be unavailable.",
            )
            .advanced(),
        );
    }
    tool
}

pub(super) fn supports_allowance(tool: &ToolDescriptor) -> bool {
    allowance_effect_supported(tool) && descriptor_work(tool).is_some()
}

fn allowance_effect_supported(tool: &ToolDescriptor) -> bool {
    if matches!(tool.effect, ToolEffect::Read | ToolEffect::WorkspaceWrite) {
        return true;
    }
    matches!(
        tool.effect,
        ToolEffect::TargetWrite | ToolEffect::ExternalAction | ToolEffect::RepositoryExecute
    ) && tool.allowance_category.is_some()
}

pub(super) fn phase_work(phase: ToolPhase) -> Option<InvestigationWork> {
    match phase {
        ToolPhase::Map => Some(InvestigationWork::Context),
        ToolPhase::Scan => Some(InvestigationWork::Discovery),
        ToolPhase::Review => Some(InvestigationWork::Review),
        ToolPhase::Report => Some(InvestigationWork::Report),
        _ => None,
    }
}

pub(super) fn descriptor_work(tool: &ToolDescriptor) -> Option<InvestigationWork> {
    let Some(category) = tool.allowance_category else {
        return phase_work(tool.phase);
    };
    Some(match category {
        AllowanceCategory::Context => InvestigationWork::Context,
        AllowanceCategory::Scope => InvestigationWork::Scope,
        AllowanceCategory::Discovery => InvestigationWork::Discovery,
        AllowanceCategory::Review => InvestigationWork::Review,
        AllowanceCategory::Report => InvestigationWork::Report,
        AllowanceCategory::Learning => InvestigationWork::Learning,
    })
}
