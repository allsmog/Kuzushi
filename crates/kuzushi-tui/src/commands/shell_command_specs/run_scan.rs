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
        command: "run <tool> [key=value ...]",
        aliases: &[
            "run .",
            "/run <tool> [key=value ...]",
            "run . [key=value ...]",
        ],
        category: ShellCommandCategory::RunScan,
        description: "run a tool with key=value options; run . uses the focused module",
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
        command: "ask [--whole-model] <question>",
        aliases: &["/ask <question>", "?text"],
        category: ShellCommandCategory::RunScan,
        description: "ask inline with bounded screen context; --whole-model attaches the map",
    },
    ShellCommandSpec {
        command: "ask cancel",
        aliases: &["/ask cancel"],
        category: ShellCommandCategory::RunScan,
        description: "cancel only the active Ask and preserve a concurrent run",
    },
    ShellCommandSpec {
        command: "queue <tool|verb>",
        aliases: &["/queue <tool>", "queue run <tool>"],
        category: ShellCommandCategory::RunScan,
        description: "queue a command to run after the current one finishes",
    },
];
