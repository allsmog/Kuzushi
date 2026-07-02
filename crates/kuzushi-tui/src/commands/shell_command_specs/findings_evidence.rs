use super::*;

pub(crate) const FINDINGS_EVIDENCE_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "findings",
        aliases: &["findings", "/f", "f", "/findings"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "open persisted findings",
    },
    ShellCommandSpec {
        command: "findings filter <expr>",
        aliases: &[
            "findings filter state:new rank:high",
            "/findings filter <expr>",
        ],
        category: ShellCommandCategory::FindingsEvidence,
        description: "open filtered findings in the Workbench",
    },
    ShellCommandSpec {
        command: "open <id>",
        aliases: &["open F-0001", "/open <id>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "open a finding alias or fingerprint",
    },
    ShellCommandSpec {
        command: "show aliases [prefix]",
        aliases: &["/show aliases [prefix]"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "list finding aliases",
    },
    ShellCommandSpec {
        command: "show runs",
        aliases: &["/show runs", "runs", "/runs"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "recent run artifacts",
    },
    ShellCommandSpec {
        command: "runs diff <left> <right>",
        aliases: &["runs diff <runA> <runB>", "runs compare <runA> <runB>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "compare findings snapshots from two runs",
    },
    ShellCommandSpec {
        command: "replay <run|latest>",
        aliases: &["/replay <run|latest>", "replay latest"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "render a run summary",
    },
    ShellCommandSpec {
        command: "trace <run>",
        aliases: &["/trace <run>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "stream run events",
    },
    ShellCommandSpec {
        command: "activity",
        aliases: &["activity", "/activity", "progress", "/progress", "/a"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "live module-progress dashboard",
    },
    ShellCommandSpec {
        command: "handoff",
        aliases: &["handoff", "/handoff", "failure", "/failure"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "latest bounded failure handoff",
    },
    ShellCommandSpec {
        command: "since <ref>",
        aliases: &["/since <ref>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "scope findings to a git ref",
    },
    ShellCommandSpec {
        command: "threats [1-4]",
        aliases: &[
            "/threats [1-4]",
            "threats summary",
            "threats dfd",
            "threats stride",
            "threats stories",
            "threats scope",
        ],
        category: ShellCommandCategory::FindingsEvidence,
        description: "threat model views",
    },
    ShellCommandSpec {
        command: "threats edit",
        aliases: &["/threats edit"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "open the editable threat model view",
    },
    ShellCommandSpec {
        command: "threats regen",
        aliases: &["/threats regen"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "Haiku-driven threat-model patch; review then /threats apply",
    },
    ShellCommandSpec {
        command: "threats ask <question>",
        aliases: &["/threats ask <question>"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "ask the agent about the current threat model",
    },
    ShellCommandSpec {
        command: "threats apply",
        aliases: &["/threats apply"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "apply the pending threat-model patch",
    },
    ShellCommandSpec {
        command: "threats reject",
        aliases: &["/threats reject"],
        category: ShellCommandCategory::FindingsEvidence,
        description: "discard the pending threat-model patch",
    },
];
