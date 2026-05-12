use super::*;

pub(crate) const RUN_SCAN_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "scan [target]",
        aliases: &["scan .", "/scan [target]"],
        category: ShellCommandCategory::RunScan,
        description: "run configured scanners",
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
        command: "pwn [verb]",
        aliases: &["/pwn", "/pwn target <path>", "/pwn auto"],
        category: ShellCommandCategory::RunScan,
        description: "open the pwn dashboard or launch pwn workflow tools",
    },
];
