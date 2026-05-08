use super::prelude::*;
use super::*;

pub(crate) fn pipeline_module() -> BuiltinModule {
    hidden_module(
        "pipeline",
        "Pipeline",
        ModuleKind::Internal,
        "Internal orchestrator DAG nodes for task selection, approval gates, and taint sub-tasks.",
        vec![],
        vec![
            dag(
                "pipeline:task-selector",
                "task-selection",
                &["context:build"],
            ),
            dag(
                "pipeline:approval-before-verification",
                "approval",
                &["triage:run"],
            ),
            dag(
                "pipeline:taint-cwe-select",
                "cwe-selection",
                &["context:build"],
            ),
        ],
    )
}

pub(crate) fn variant_module() -> BuiltinModule {
    builtin_module(
        "variant",
        "Variant Hunter",
        ModuleKind::Offense,
        "Lift exploit patterns from confirmed findings and hunt sibling variants.",
        vec![
            tool_with_options(
                "variant:lift-pattern",
                "Lift a reusable vulnerability pattern from a confirmed finding.",
                vec![fingerprint_option(), model_option()],
            ),
            tool_with_options(
                "variant:hunt",
                "Hunt variants of a confirmed finding.",
                vec![
                    target_option(),
                    fingerprint_option(),
                    max_findings_option(25),
                    model_option(),
                ],
            ),
        ],
        vec![dag("variant:hunt", "findings", &["variant:lift-pattern"])],
    )
}

pub(crate) fn ndiff_module() -> BuiltinModule {
    builtin_module(
        "ndiff",
        "N-Day Diff Hunter",
        ModuleKind::Intel,
        "Fetch CVE fix context, extract fix patterns, and hunt n-day variants.",
        vec![
            tool_with_options(
                "ndiff:fetch-cve",
                "Fetch CVE and patch metadata.",
                vec![opt("id", OptionType::String, "CVE or advisory id to fetch.").required()],
            ),
            tool_with_options(
                "ndiff:extract-fix-pattern",
                "Extract a vulnerability fix pattern from a patch.",
                vec![model_option()],
            ),
            tool_with_options(
                "ndiff:hunt-variants",
                "Hunt variants using an extracted n-day fix pattern.",
                vec![target_option(), max_findings_option(25), model_option()],
            ),
        ],
        vec![dag(
            "ndiff:hunt-variants",
            "findings",
            &["ndiff:extract-fix-pattern"],
        )],
    )
}

pub(crate) fn randori_module() -> BuiltinModule {
    builtin_module(
        "randori",
        "Randori",
        ModuleKind::Intel,
        "PASTA and randori threat-model generation.",
        vec![
            tool_with_options(
                "randori:pasta",
                "Generate a PASTA threat model.",
                vec![target_option(), model_option()],
            ),
            tool_with_options(
                "randori:threat-model",
                "Generate a randori threat model.",
                vec![target_option(), model_option()],
            ),
        ],
        vec![dag(
            "randori:threat-model",
            "threat-model",
            &["context:build"],
        )],
    )
}
