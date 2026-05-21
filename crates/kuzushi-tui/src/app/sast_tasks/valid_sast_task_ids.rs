use super::*;

#[derive(Debug, Clone, Copy)]
pub(crate) struct SastTaskCapability {
    pub(crate) id: &'static str,
    pub(crate) scan_task: &'static str,
    pub(crate) cost: &'static str,
    pub(crate) notes: &'static str,
    pub(crate) default_enabled: bool,
    pub(crate) toggleable: bool,
}

pub(crate) const SAST_TASK_CAPABILITIES: &[SastTaskCapability] = &[
    SastTaskCapability {
        id: "semgrep",
        scan_task: "semgrep",
        cost: "low",
        notes: "pattern scanner",
        default_enabled: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "codeql",
        scan_task: "codeql",
        cost: "high",
        notes: "semantic query scanner",
        default_enabled: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "dep-hygiene",
        scan_task: "dep-hygiene",
        cost: "low",
        notes: "dependency manifest hygiene",
        default_enabled: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "cargo-audit",
        scan_task: "cargo-audit",
        cost: "medium",
        notes: "Rust advisory scanner",
        default_enabled: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "secret-scan",
        scan_task: "secret-scan",
        cost: "low",
        notes: "local secret patterns",
        default_enabled: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "iac-scan",
        scan_task: "iac-scan",
        cost: "low",
        notes: "IaC misconfiguration scanner",
        default_enabled: true,
        toggleable: true,
    },
    SastTaskCapability {
        id: "license-scan",
        scan_task: "license-scan",
        cost: "low",
        notes: "package license risk scanner",
        default_enabled: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "agentic",
        scan_task: "agentic",
        cost: "high",
        notes: "model-backed detector set; run via sast:scan",
        default_enabled: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "offense-review",
        scan_task: "offense-review",
        cost: "high",
        notes: "threat-model-guided review; run via sast:scan",
        default_enabled: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "taint-iris",
        scan_task: "taint-iris",
        cost: "high",
        notes: "source-to-sink analysis; run via sast:scan",
        default_enabled: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "taint-iris-next",
        scan_task: "taint-iris-next",
        cost: "high",
        notes: "next taint workflow; run via sast:scan",
        default_enabled: false,
        toggleable: true,
    },
    SastTaskCapability {
        id: "systems-hunt",
        scan_task: "systems-hunt",
        cost: "high",
        notes: "deferred exact opt-in systems invariant hunt; run via sast:scan",
        default_enabled: false,
        toggleable: true,
    },
];

pub(crate) fn valid_sast_task_ids() -> Vec<&'static str> {
    SAST_TASK_CAPABILITIES.iter().map(|task| task.id).collect()
}

pub(crate) fn unknown_sast_task_message(raw_id: &str) -> String {
    format!(
        "unknown SAST task {raw_id:?}. Valid task IDs: {}. Next: /tasks",
        valid_sast_task_ids().join(", ")
    )
}
