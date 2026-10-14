use super::*;

pub(crate) fn suppress_module() -> BuiltinModule {
    builtin_module(
        "suppress",
        "Suppress",
        ModuleKind::Defense,
        "Compose suppression rules (mute false positives, scope, severity, expiry).",
        suppression_tools(),
        vec![],
    )
}

fn suppression_tools() -> Vec<ToolDescriptor> {
    vec![
            tool_with_options("suppress:add", "Add a suppression rule.", suppress_add_options())
                .with_policy(workspace_policy(
                    ToolPhase::Review,
                    RuntimeRequirement::Never,
                    FindingStoreRequirement::Required,
                ))
                .without_phase_result(),
            tool_with_options(
                "suppress:list",
                "List suppression rules and reconcile expired or removed rule effects in the findings ledger.",
                vec![],
            )
            .with_policy(workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            ))
            .without_phase_result(),
            tool_with_options(
                "suppress:remove",
                "Remove a suppression rule by id and reopen the findings it muted.",
                vec![opt("id", OptionType::String, "Suppression rule id to remove.")
                    .aliases(&["ruleId", "rule_id"])
                    .required()],
            )
            .with_policy(workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            ))
            .without_phase_result(),
        ]
}

#[cfg(test)]
mod tests;

fn suppress_add_options() -> Vec<OptionSpec> {
    let mut options = suppress_predicate_options();
    options.extend(suppress_metadata_options());
    options
}

fn suppress_predicate_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "finding",
            OptionType::String,
            "Finding reference (alias, identity, or fingerprint).",
        )
        .aliases(&["finding_id", "id"]),
        opt(
            "rule",
            OptionType::String,
            "Match findings with this rule id.",
        )
        .aliases(&["rule_id"]),
        opt(
            "path",
            OptionType::String,
            "Match findings whose file path matches this glob.",
        ),
        opt("tool", OptionType::String, "Match findings from this tool."),
        opt(
            "module",
            OptionType::String,
            "Match findings from this module id.",
        ),
        opt(
            "severityBelow",
            OptionType::String,
            "Mute findings strictly below this severity.",
        )
        .aliases(&["severity_below"]),
        opt(
            "scopeStatus",
            OptionType::String,
            "Match findings with this scope verdict.",
        )
        .aliases(&["scope_status"]),
    ]
}

fn suppress_metadata_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "reason",
            OptionType::String,
            "Suppression reason (false-positive, acceptable-risk, ...).",
        )
        .required(),
        opt(
            "statement",
            OptionType::String,
            "Why this suppression is justified (required).",
        )
        .required(),
        opt(
            "days",
            OptionType::Int,
            "Auto-expire the rule after this many days.",
        )
        .aliases(&["expires_days"]),
        opt(
            "actor",
            OptionType::String,
            "Who authored this suppression.",
        )
        .aliases(&["author"]),
        opt(
            "ruleId",
            OptionType::String,
            "Explicit rule id (defaults to a derived hash).",
        )
        .advanced(),
    ]
}
