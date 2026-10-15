use serde_json::{json, Value};

pub(super) fn candidate_coverage() -> Value {
    json!({
        "complete": false,
        "method": "limited-manifest-candidates",
        "recommendedInventory": "sbom-scan:scan",
        "limitations": [
            "npm, Cargo and Python manifests are inspected only at the selected root.",
            "Immediate-child Go modules are inspected only when root collection found no packages.",
            "Bazel traversal is bounded but has no ledger of skipped or unreadable paths.",
            "An empty selected subtree may read manifests from an enclosing Bazel workspace.",
            "Per-file reads are bounded; aggregate inspection and in-flight cancellation are not enforced."
        ]
    })
}

pub(super) fn candidate_warning(empty: bool) -> &'static str {
    if empty {
        "No package candidates extracted. Coverage is incomplete. Use sbom-scan:scan for dependency inventory."
    } else {
        "Coverage is incomplete. Nested manifests may be omitted. Use sbom-scan:scan for dependency inventory."
    }
}
