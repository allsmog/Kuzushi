pub(crate) struct CanonicalRunArtifactSpec {
    pub(crate) leaf: &'static str,
    pub(crate) label: &'static str,
    pub(crate) kind: &'static str,
}

pub(crate) const CANONICAL_RUN_ARTIFACTS: [CanonicalRunArtifactSpec; 6] = [
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

pub(crate) const SCAN_PIPELINE_ARTIFACTS: [CanonicalRunArtifactSpec; 4] = [
    CanonicalRunArtifactSpec {
        leaf: "scan-input.json",
        label: "scan input",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "triage.jsonl",
        label: "scan triage events",
        kind: "jsonl",
    },
    CanonicalRunArtifactSpec {
        leaf: "verify.jsonl",
        label: "scan verification events",
        kind: "jsonl",
    },
    CanonicalRunArtifactSpec {
        leaf: "patch.jsonl",
        label: "scan patch events",
        kind: "jsonl",
    },
];

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

pub(crate) fn scan_pipeline_artifact_spec(leaf: &str) -> Option<&'static CanonicalRunArtifactSpec> {
    SCAN_PIPELINE_ARTIFACTS
        .iter()
        .find(|spec| spec.leaf == leaf)
}
