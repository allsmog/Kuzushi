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
        leaf: "items.jsonl",
        label: "semantic run items",
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

pub(crate) const OPTIONAL_RUN_ARTIFACTS: [CanonicalRunArtifactSpec; 3] = [
    CanonicalRunArtifactSpec {
        leaf: "inherited-allowance.json",
        label: "Inherited accounting context",
        kind: "json",
    },
    CanonicalRunArtifactSpec {
        leaf: "report.sarif",
        label: "SARIF report",
        kind: "sarif",
    },
    CanonicalRunArtifactSpec {
        leaf: "stages.jsonl",
        label: "tool stage receipts",
        kind: "jsonl",
    },
];

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

pub(crate) const SCAN_PIPELINE_ARTIFACTS: [CanonicalRunArtifactSpec; 5] = [
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
    CanonicalRunArtifactSpec {
        leaf: "phase-stages.jsonl",
        label: "scan phase stage receipts",
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

/// One immutable source record belongs to one observed tool call.
pub(crate) fn scan_start_source_artifact_leaf(producer: crate::run_lifecycle::RunItemId) -> String {
    format!("source-start-{producer}.json")
}

/// The leaf file name a declared artifact path names.
///
/// A declared path can be stated against the run directory or as an absolute
/// path, so the leaf is what identifies the artifact. A path with no final
/// component (`.`, `..`, the empty string) is returned unchanged so a caller
/// never silently reads it as some other artifact.
pub(crate) fn declared_artifact_leaf(path: &str) -> &str {
    std::path::Path::new(path)
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or(path)
}

/// `true` when a declared artifact path names the canonical artifact `leaf`.
///
/// Call sites asked this with `str::ends_with`, which answers yes whenever one
/// artifact's name merely ends with another's. Kuzushi writes two such pairs
/// itself — `scan-input.json` ends with `input.json`, and `phase-stages.jsonl`
/// ends with `stages.jsonl` — so a scan run's own pipeline artifacts were read
/// as the tool-input and tool-stage artifacts that run never wrote.
///
/// Unlike a reported *source* path, which is literal detector data and keeps
/// `\` as a filename byte (see `findings::domain::reported_source_path`), a
/// declared artifact path is one Kuzushi built from a run directory, so the
/// platform's own separators are the right ones to read.
pub(crate) fn declared_path_names_artifact(path: &str, leaf: &str) -> bool {
    declared_artifact_leaf(path) == leaf
}

#[cfg(test)]
mod tests {
    use super::{
        declared_artifact_leaf, declared_path_names_artifact, CANONICAL_RUN_ARTIFACTS,
        OPTIONAL_RUN_ARTIFACTS, SCAN_PIPELINE_ARTIFACTS, TOOL_INPUT_ARTIFACTS,
        TOOL_RESULT_ARTIFACTS,
    };

    #[test]
    fn a_declared_path_names_the_artifact_its_leaf_names_against_any_root() {
        assert!(declared_path_names_artifact("run.json", "run.json"));
        assert!(declared_path_names_artifact(
            ".kuzushi/v3/runs/run-1/items.jsonl",
            "items.jsonl"
        ));
        assert!(declared_path_names_artifact(
            "/home/op/target/.kuzushi/v3/runs/run-1/report.md",
            "report.md"
        ));
    }

    #[test]
    fn a_shared_name_ending_names_a_different_artifact() {
        // Both pairs are artifacts Kuzushi writes itself.
        assert!(!declared_path_names_artifact(
            "scan-input.json",
            "input.json"
        ));
        assert!(!declared_path_names_artifact(
            "runs/run-1/phase-stages.jsonl",
            "stages.jsonl"
        ));
        assert!(!declared_path_names_artifact("prior-run.json", "run.json"));
        assert!(!declared_path_names_artifact(
            "input.json",
            "scan-input.json"
        ));
    }

    #[test]
    fn no_contracted_leaf_is_read_as_another_one_it_merely_ends_like() {
        let leaves: Vec<&str> = CANONICAL_RUN_ARTIFACTS
            .iter()
            .chain(OPTIONAL_RUN_ARTIFACTS.iter())
            .chain(TOOL_INPUT_ARTIFACTS.iter())
            .chain(TOOL_RESULT_ARTIFACTS.iter())
            .chain(SCAN_PIPELINE_ARTIFACTS.iter())
            .map(|spec| spec.leaf)
            .collect();
        let mut shared_endings = 0;
        for declared in &leaves {
            for leaf in &leaves {
                assert_eq!(
                    declared_path_names_artifact(declared, leaf),
                    declared == leaf,
                    "{declared} must name {leaf} only when it is that artifact"
                );
                if declared != leaf && declared.ends_with(leaf) {
                    shared_endings += 1;
                }
            }
        }
        // `scan-input.json`/`input.json` and `phase-stages.jsonl`/
        // `stages.jsonl` are the pairs a suffix match confuses. A new leaf
        // that shares an ending with another belongs in that list.
        assert_eq!(
            shared_endings, 2,
            "a contracted leaf newly shares an ending with another one"
        );
    }

    #[test]
    fn a_path_without_a_final_component_is_left_as_it_was_stated() {
        for path in ["", ".", "..", "runs/.."] {
            assert_eq!(declared_artifact_leaf(path), path);
            assert!(!declared_path_names_artifact(path, "run.json"));
        }
        assert_eq!(declared_artifact_leaf("runs/run-1/run.json/"), "run.json");
    }
}
