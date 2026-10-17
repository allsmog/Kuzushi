use super::*;

pub(crate) fn findings_module() -> BuiltinModule {
    let mut tools = vec![
        findings_list_tool(),
        findings_dismiss_tool(),
        findings_ground_tool(),
        findings_chains_tool(),
    ];
    tools.extend(super::findings_relationships::relationship_tools());
    tools.push(super::findings_groups::groups_tool());
    tools.extend(super::findings_goals::tools());
    tools.extend(super::findings_lessons::lesson_tools());
    tools.push(super::findings_lessons::generation_tool());
    tools.push(super::findings_source_review::tool());
    builtin_module(
        "findings",
        "Findings",
        ModuleKind::Defense,
        "Persist and inspect findings in SQLite.",
        tools,
        vec![],
    )
}

fn findings_list_tool() -> ToolDescriptor {
    tool_with_options(
        "findings:list",
        "List persisted findings.",
        findings_list_options(),
    )
    .with_policy(ToolPolicy::new(
        ToolPhase::Review,
        RuntimeRequirement::Never,
        ToolEffect::Read,
        WorkspaceRequirement::Required,
        FindingStoreRequirement::Required,
    ))
}

fn findings_dismiss_tool() -> ToolDescriptor {
    tool_with_options(
        "findings:dismiss",
        "Dismiss a finding with an auditable, SARIF-compatible reason.",
        findings_dismiss_options(),
    )
    .with_policy(workspace_policy(
        ToolPhase::Review,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Required,
    ))
    .without_phase_result()
}

fn findings_ground_tool() -> ToolDescriptor {
    tool_with_options(
        "findings:ground",
        "Re-check every open finding's citation against the target \
         tree at the current revision. Reports grounded / line-drift \
         / file-missing counts and audits newly stale anchors. \
         Citation inspection only; never retires a finding or changes its verdict.",
        findings_ground_options(),
    )
    .with_policy(workspace_policy(
        ToolPhase::Review,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Required,
    ))
    .without_phase_result()
}

fn findings_chains_tool() -> ToolDescriptor {
    tool_with_options(
        "findings:chains",
        "Experimental advisory relationships over recorded confirmed findings. \
         Output limits do not bound pair enumeration; large histories and \
         in-progress cancellation remain unqualified. No model calls. \
         Does not complete Review.",
        findings_chains_options(),
    )
    .with_policy(workspace_policy(
        ToolPhase::Review,
        RuntimeRequirement::Never,
        FindingStoreRequirement::Required,
    ))
    .without_phase_result()
    .with_discovery_maturity(ModuleMaturity::Labs)
}

fn findings_ground_options() -> Vec<OptionSpec> {
    vec![opt(
        "limit",
        OptionType::Int,
        "Maximum ledger candidates selected in stable identity order (0 to 100000). Suppressed/rekeyed rows are excluded after selection; additional candidates require a separate request.",
    )
    .default(json!(500))
    .advanced(),
    opt("maxBytesPerFile", OptionType::Int, "Exact citation source read limit per file, from 1 to 8388608 bytes.").default(json!(8 * 1024 * 1024)).advanced(),
    opt("maxTotalBytes", OptionType::Int, "Shared source read limit from 1 to 536870912 bytes. Repeated citations share one captured file.").default(json!(64 * 1024 * 1024)).advanced(),
    ]
}

fn findings_chains_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "maxChains",
            OptionType::Int,
            "Maximum ranked chain candidates to return.",
        )
        .aliases(&["max_chains"])
        .default(json!(16)),
        opt(
            "output",
            OptionType::Path,
            "Optional target-relative path for the chain report JSON \
             (e.g. .kuzushi/v3/reports/chains.json).",
        )
        .state_write()
        .advanced(),
        opt(
            "persistFindings",
            OptionType::Bool,
            "Persist each chain candidate as a triageable finding (tool \
             `chains`, rule `chains/candidate`) so a follow-up triage:run \
             can verdict the chain itself. Re-folds are idempotent.",
        )
        .aliases(&["persist_findings"])
        .default(json!(false)),
    ]
}

fn findings_dismiss_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "fingerprint",
            OptionType::String,
            "Finding fingerprint or FI- alias.",
        )
        .aliases(&["finding", "reference", "id"])
        .required(),
        opt(
            "reason",
            OptionType::Enum,
            "Dismissal reason (SARIF-compatible).",
        )
        .choices(&[
            "false_positive",
            "acceptable_risk",
            "wont_fix",
            "used_in_tests",
            "no_time_to_fix",
        ])
        .required(),
        opt("note", OptionType::String, "Free-text justification.").required(),
        opt(
            "author",
            OptionType::String,
            "Who is dismissing (defaults to the resolved operator).",
        ),
    ]
}

fn findings_list_options() -> Vec<OptionSpec> {
    let mut options = findings_basic_options();
    options.extend(findings_page_options());
    options.extend(findings_triage_options());
    options.extend(findings_provenance_options());
    options.push(
        opt(
            "vulnSource",
            OptionType::StringList,
            "Discovery channel filter.",
        )
        .aliases(&["source", "vuln_source"]),
    );
    options
}

fn findings_basic_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "target",
            OptionType::Path,
            "Workspace target for provenance filters.",
        )
        .workspace_read()
        .advanced(),
        opt("limit", OptionType::Int, "Maximum findings to return.").default(json!(50)),
        opt(
            "filter",
            OptionType::String,
            "Search expression over rank, verdict, state, source, file, title, and run.",
        )
        .advanced(),
        opt(
            "name",
            OptionType::String,
            "Substring filter for finding titles.",
        ),
        opt("filePath", OptionType::String, "File path filter.").aliases(&["file_path"]),
        opt(
            "filePaths",
            OptionType::StringList,
            "Exact file paths, matching any supplied path. Other filters still apply.",
        )
        .aliases(&["file_paths"])
        .advanced(),
        opt(
            "severity",
            OptionType::StringList,
            "Severity filter: critical, high, medium, low, info.",
        ),
    ]
}

fn findings_page_options() -> Vec<OptionSpec> {
    vec![
        opt(
            "batchId",
            OptionType::String,
            "Read identities observed in this finite study, including incomplete attempts. Membership applies before paging; aliases and decisions remain those of workspace history.",
        )
        .aliases(&["batch_id", "batch"])
        .advanced(),
        opt(
            "cursor",
            OptionType::String,
            "Continue a findings page from its returned cursor.",
        )
        .advanced(),
        opt(
            "anchor",
            OptionType::String,
            "Reload an exact finding anchor. Continuity anchors follow one unambiguous identity after a generation is replaced.",
        )
        .advanced(),
        opt(
            "order",
            OptionType::Enum,
            "Order findings before selecting a page.",
        )
        .choices(&["ledger", "confidence"])
        .default(json!("ledger")),
    ]
}

fn findings_triage_options() -> Vec<OptionSpec> {
    vec![
        opt("verdict", OptionType::StringList, "Triage verdict filter."),
        opt(
            "state",
            OptionType::StringList,
            "Filter: open, reviewing, confirmed, to_fix, dismissed, not_observed, untriaged or triaged. Not observed does not mean fixed.",
        )
        .advanced(),
    ]
}

fn findings_provenance_options() -> Vec<OptionSpec> {
    vec![
        opt("runId", OptionType::StringList, "Scan/run id filter.")
            .aliases(&["run_id", "run"])
            .advanced(),
        opt("sha", OptionType::StringList, "Target revision SHA filter.")
            .aliases(&["rev", "revision"])
            .advanced(),
        opt("branch", OptionType::StringList, "Target branch filter.").advanced(),
        opt(
            "dirty",
            OptionType::StringList,
            "Target dirty-state filter: dirty or clean.",
        )
        .advanced(),
    ]
}
