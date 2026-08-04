use super::*;

pub(crate) const RUN_SCAN_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "demo",
        aliases: &["demo", "/demo"],
        category: ShellCommandCategory::RunScan,
        description: "run a 90-second offline fixture scan; no key, model, or external scanner",
    },
    ShellCommandSpec {
        command: "full [target]",
        aliases: &[
            "full .",
            "/full [target]",
            "pipeline [target]",
            "/pipeline [target]",
        ],
        category: ShellCommandCategory::RunScan,
        description:
            "guide Map → Scan, then hand off to Review or Report; `full .` explicitly selects cwd",
    },
    ShellCommandSpec {
        command: "run <tool> [json]",
        aliases: &["run .", "/run <tool> [json]", "run . [json]"],
        category: ShellCommandCategory::RunScan,
        description: "dispatch a tool; run . is shell-only focused-module shorthand",
    },
    ShellCommandSpec {
        command: "recon:import <amass|httpx|nuclei|nmap-xml|burp-xml|har> <path>",
        aliases: &[
            "recon import <format> <path>",
            "/recon:import <format> <path>",
        ],
        category: ShellCommandCategory::RunScan,
        description: "import an external reconnaissance export through the registered recon tool",
    },
    ShellCommandSpec {
        command: "ask <question>",
        aliases: &["/ask <question>", "?text"],
        category: ShellCommandCategory::RunScan,
        description: "explicit agent question (stays on the current view)",
    },
    ShellCommandSpec {
        command: "queue <tool|verb>",
        aliases: &["/queue <tool>", "queue run <tool>"],
        category: ShellCommandCategory::RunScan,
        description: "queue a command to run after the current one finishes",
    },
];
