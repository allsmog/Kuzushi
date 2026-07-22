use super::*;

pub(crate) fn findings_module() -> BuiltinModule {
    builtin_module(
        "findings",
        "Findings",
        ModuleKind::Defense,
        "Persist and inspect findings in SQLite.",
        vec![
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
            )),
            tool_with_options(
                "findings:dismiss",
                "Dismiss a finding with an auditable, SARIF-compatible reason.",
                findings_dismiss_options(),
            )
            .with_policy(workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            )),
            tool_with_options(
                "findings:chains",
                "Deterministically fold confirmed findings into ranked \
                 entry→pivot→impact chain candidates per code surface. \
                 Advisory leads only; no model calls.",
                findings_chains_options(),
            )
            .with_policy(workspace_policy(
                ToolPhase::Review,
                RuntimeRequirement::Never,
                FindingStoreRequirement::Required,
            )),
        ],
        vec![],
    )
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
            "severity",
            OptionType::StringList,
            "Severity filter: critical, high, medium, low, info.",
        ),
    ]
}

fn findings_triage_options() -> Vec<OptionSpec> {
    vec![
        opt("verdict", OptionType::StringList, "Triage verdict filter."),
        opt(
            "state",
            OptionType::StringList,
            "Triage state filter: untriaged or triaged.",
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
