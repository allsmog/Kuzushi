//! Declarative scan-task resource claims.

use super::{workspace_exclusive, ParallelSafety};

pub(super) fn registered_task_claim(task: &str) -> Option<(&'static str, ParallelSafety)> {
    TASK_RESOURCE_CLAIMS.iter().find_map(|claim| {
        claim.aliases.contains(&task).then(|| {
            let safety = match claim.kind {
                ClaimKind::SharedRead => ParallelSafety::SharedRead,
                ClaimKind::Unknown => ParallelSafety::Unknown,
                ClaimKind::WorkspaceExclusive(resource) => workspace_exclusive(resource),
            };
            (claim.task, safety)
        })
    })
}

#[derive(Clone, Copy)]
enum ClaimKind {
    SharedRead,
    WorkspaceExclusive(&'static str),
    Unknown,
}

struct TaskResourceClaim {
    task: &'static str,
    aliases: &'static [&'static str],
    kind: ClaimKind,
}

const TASK_RESOURCE_CLAIMS: &[TaskResourceClaim] = &[
    shared_read("semgrep", &["semgrep", "semgrep:scan"]),
    exclusive(
        "codeql",
        &["codeql", "codeql:scan"],
        "workspace-codeql-database",
    ),
    shared_read("dep-hygiene", &["dep-hygiene", "dep-hygiene:check"]),
    shared_read("govulncheck", &["govulncheck", "govulncheck:scan"]),
    shared_read("cargo-audit", &["cargo-audit", "cargo-audit:scan"]),
    shared_read("secret-scan", &["secret-scan", "secret-scan:scan"]),
    shared_read("license-scan", &["license-scan", "license-scan:scan"]),
    shared_read("iac-scan", &["iac-scan", "iac-scan:scan"]),
    unknown("agentic", &["agentic", "agentic-sast", "agentic-sast:scan"]),
    unknown(
        "offense-review",
        &[
            "carlini",
            "threat-hunt",
            "carlini-threat-hunt",
            "carlini-threat-hunt:run",
            "offense-review",
            "offense-review:threat-hunt",
        ],
    ),
    unknown(
        "systems-hunt",
        &[
            "systems",
            "systems-hunt",
            "systems-hunt:systems-hunt",
            "systems-hunt:systems-context-gatherer",
            "systems-hunt:systems-invariant-extract",
            "systems-hunt:systems-trigger-synth",
            "deep-semantic",
            "deep-semantic-hunt",
            "systems-hunt:deep-semantic-hunt",
        ],
    ),
    unknown(
        "taint-iris-next",
        &[
            "taint",
            "iris",
            "taint-iris",
            "taint-iris:hunt",
            "taint-iris-next",
            "iris-next",
            "taint-next",
            "taint-iris-next:hunt",
        ],
    ),
];

const fn shared_read(task: &'static str, aliases: &'static [&'static str]) -> TaskResourceClaim {
    TaskResourceClaim {
        task,
        aliases,
        kind: ClaimKind::SharedRead,
    }
}

const fn exclusive(
    task: &'static str,
    aliases: &'static [&'static str],
    resource: &'static str,
) -> TaskResourceClaim {
    TaskResourceClaim {
        task,
        aliases,
        kind: ClaimKind::WorkspaceExclusive(resource),
    }
}

const fn unknown(task: &'static str, aliases: &'static [&'static str]) -> TaskResourceClaim {
    TaskResourceClaim {
        task,
        aliases,
        kind: ClaimKind::Unknown,
    }
}
