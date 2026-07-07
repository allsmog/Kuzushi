pub(crate) struct CanonicalRunArtifactSpec {
    pub(crate) leaf: &'static str,
    pub(crate) label: &'static str,
    pub(crate) kind: &'static str,
}

pub(crate) const CANONICAL_RUN_ARTIFACTS: [CanonicalRunArtifactSpec; 13] = [
    CanonicalRunArtifactSpec {
        leaf: "run.json",
        label: "run metadata",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "events.jsonl",
        label: "run events",
        kind: "jsonl",
    },
    CanonicalRunArtifactSpec {
        leaf: "trace.jsonl",
        label: "runtime trace",
        kind: "jsonl",
    },
    CanonicalRunArtifactSpec {
        leaf: "context.json",
        label: "context snapshot",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "attack-surface.json",
        label: "attack surface",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "threat-model.json",
        label: "threat model",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "recommendations.json",
        label: "recommendations",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "strategy.json",
        label: "strategy proposals",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "findings.json",
        label: "findings",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "proof.json",
        label: "proof",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "failures.json",
        label: "failure handoff",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "report.md",
        label: "report",
        kind: "markdown",
    },
    CanonicalRunArtifactSpec {
        leaf: "artifacts.json",
        label: "artifact manifest",
        kind: "json",
    },
];

pub(crate) const OPTIONAL_RUN_ARTIFACTS: [CanonicalRunArtifactSpec; 1] =
    [CanonicalRunArtifactSpec {
        leaf: "report.sarif",
        label: "SARIF report",
        kind: "sarif",
    }];

pub(crate) const TOOL_RESULT_ARTIFACTS: [CanonicalRunArtifactSpec; 1] =
    [CanonicalRunArtifactSpec {
        leaf: "result.json",
        label: "tool result",
        kind: "json",
    }];

pub(crate) const TOOL_INPUT_ARTIFACTS: [CanonicalRunArtifactSpec; 1] = [CanonicalRunArtifactSpec {
    leaf: "input.json",
    label: "tool input",
    kind: "json",
}];

pub(crate) fn canonical_run_artifact_spec(leaf: &str) -> Option<&'static CanonicalRunArtifactSpec> {
    CANONICAL_RUN_ARTIFACTS
        .iter()
        .find(|spec| spec.leaf == leaf)
}

pub(crate) fn optional_run_artifact_spec(leaf: &str) -> Option<&'static CanonicalRunArtifactSpec> {
    OPTIONAL_RUN_ARTIFACTS.iter().find(|spec| spec.leaf == leaf)
}

pub(crate) fn tool_result_artifact_spec(leaf: &str) -> Option<&'static CanonicalRunArtifactSpec> {
    TOOL_RESULT_ARTIFACTS.iter().find(|spec| spec.leaf == leaf)
}

pub(crate) fn tool_input_artifact_spec(leaf: &str) -> Option<&'static CanonicalRunArtifactSpec> {
    TOOL_INPUT_ARTIFACTS.iter().find(|spec| spec.leaf == leaf)
}
