use super::*;

pub(crate) const CONTEXT_KB_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "context",
        aliases: &["/context"],
        category: ShellCommandCategory::ContextKb,
        description: "show current context snapshot",
    },
    ShellCommandSpec {
        command: "context build",
        aliases: &["/context build"],
        category: ShellCommandCategory::ContextKb,
        description: "build repository context",
    },
    ShellCommandSpec {
        command: "context status",
        aliases: &["/context status"],
        category: ShellCommandCategory::ContextKb,
        description: "show context status",
    },
    ShellCommandSpec {
        command: "context regen <slice>",
        aliases: &["/context regen <slice>"],
        category: ShellCommandCategory::ContextKb,
        description: "rebuild all, repo, or app-model",
    },
    ShellCommandSpec {
        command: "kb [module]",
        aliases: &["attachments", "/kb [module]"],
        category: ShellCommandCategory::ContextKb,
        description: "show local KB attachments",
    },
    ShellCommandSpec {
        command: "attach <path-or-url>",
        aliases: &["/attach <path-or-url>"],
        category: ShellCommandCategory::ContextKb,
        description: "record local file or URL metadata",
    },
    ShellCommandSpec {
        command: "detach <id>",
        aliases: &["/detach <id>"],
        category: ShellCommandCategory::ContextKb,
        description: "remove a KB attachment",
    },
    ShellCommandSpec {
        command: "reparse <id>",
        aliases: &["/reparse <id>"],
        category: ShellCommandCategory::ContextKb,
        description: "refresh local attachment metadata",
    },
    ShellCommandSpec {
        command: "workspace",
        aliases: &["/workspace", "workspace status"],
        category: ShellCommandCategory::ContextKb,
        description: "show target and state status",
    },
    ShellCommandSpec {
        command: "workspace export findings <path>",
        aliases: &[
            "/workspace export findings <path>",
            "findings export <path>",
        ],
        category: ShellCommandCategory::ContextKb,
        description: "export findings JSON or JSONL",
    },
];
