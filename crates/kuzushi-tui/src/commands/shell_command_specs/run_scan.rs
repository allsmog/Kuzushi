use super::*;

pub(crate) const RUN_SCAN_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "demo",
        aliases: &["demo", "/demo"],
        category: ShellCommandCategory::RunScan,
        description: "run a 90-second offline fixture scan; no key, model, or external scanner",
    },
    ShellCommandSpec {
        command: "scan [target]",
        aliases: &["scan .", "/scan [target]"],
        category: ShellCommandCategory::RunScan,
        description: "open the guided workflow for a target; `scan .` opts into cwd",
    },
    ShellCommandSpec {
        command: "run <tool> [json]",
        aliases: &["run .", "/run <tool> [json]", "run . [json]"],
        category: ShellCommandCategory::RunScan,
        description: "dispatch a tool; run . is shell-only focused-module shorthand",
    },
    ShellCommandSpec {
        command: "ask <question>",
        aliases: &["/ask <question>", "?text"],
        category: ShellCommandCategory::RunScan,
        description: "explicit agent question",
    },
    ShellCommandSpec {
        command: "queue <tool|verb>",
        aliases: &["/queue <tool>", "queue run <tool>"],
        category: ShellCommandCategory::RunScan,
        description: "queue a command to run after the current one finishes",
    },
];
