use super::*;

pub(crate) fn findings_module() -> BuiltinModule {
    builtin_module(
        "findings",
        "Findings",
        ModuleKind::Defense,
        "Persist and inspect findings in SQLite.",
        vec![tool_with_options(
            "findings:list",
            "List persisted findings.",
            findings_list_options(),
        )],
        vec![],
    )
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
        opt("filePath", OptionType::Path, "File path filter.").aliases(&["file_path"]),
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
