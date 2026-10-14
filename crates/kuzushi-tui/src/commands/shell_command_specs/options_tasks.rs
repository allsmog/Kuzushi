use super::*;

pub(crate) const OPTIONS_TASK_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "options [tool]",
        aliases: &["/options [tool]", "/show options [tool]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "show tool options",
    },
    ShellCommandSpec {
        command: "show advanced [tool]",
        aliases: &["/show advanced [tool]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "advanced and evasion options",
    },
    ShellCommandSpec {
        command: "show missing [tool]",
        aliases: &["/show missing [tool]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "required options without values",
    },
    ShellCommandSpec {
        command: "set <key> <value>",
        aliases: &["/set <key> <value>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "set a session option or shell preference",
    },
    ShellCommandSpec {
        command: "setg <key> <value>",
        aliases: &["/setg <key> <value>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "set a persistent option or shell preference",
    },
    ShellCommandSpec {
        command: "unset <key>",
        aliases: &["/unset <key>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "clear a session option or shell preference",
    },
    ShellCommandSpec {
        command: "unsetg <key>",
        aliases: &["/unsetg <key>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "clear a persistent option or shell preference",
    },
    ShellCommandSpec {
        command: "tasks",
        aliases: &["/tasks"],
        category: ShellCommandCategory::OptionsTasks,
        description: "choose SAST scanner tasks",
    },
    ShellCommandSpec {
        command: "strategy",
        aliases: &["/strategy", "strategies", "strategy queue"],
        category: ShellCommandCategory::OptionsTasks,
        description: "show proposed phase strategies",
    },
    ShellCommandSpec {
        command: "strategy inspect <id>",
        aliases: &["/strategy inspect <id>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "read one proposal's recorded approval, outcome and source without execution",
    },
    ShellCommandSpec {
        command: "strategy approve <id>",
        aliases: &["/strategy approve <id>", "strategy keep <id>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "approve/keep a queued strategy proposal",
    },
    ShellCommandSpec {
        command: "strategy reject <id>",
        aliases: &["/strategy reject <id>", "strategy skip <id>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "reject/skip a queued strategy proposal",
    },
    ShellCommandSpec {
        command: "strategy fire",
        aliases: &["/strategy fire", "strategy run"],
        category: ShellCommandCategory::OptionsTasks,
        description: "run the next approved strategy proposal",
    },
    ShellCommandSpec {
        command: "strategy correct <id> <strategy>",
        aliases: &[
            "/strategy correct <id> <strategy>",
            "strategy correct <id> <strategy> --workspace",
        ],
        category: ShellCommandCategory::OptionsTasks,
        description: "record a strategy correction",
    },
    ShellCommandSpec {
        command: "task block <id>",
        aliases: &["task deny <id>", "/task block <id>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "block a SAST task",
    },
    ShellCommandSpec {
        command: "task allow <id>",
        aliases: &["/task allow <id>", "task unblock <id>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "allow a SAST task",
    },
    ShellCommandSpec {
        command: "task toggle [id]",
        aliases: &["/task toggle [id]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "toggle a SAST task",
    },
    ShellCommandSpec {
        command: "task mode auto|manual|toggle",
        aliases: &["/task mode auto|manual|toggle"],
        category: ShellCommandCategory::OptionsTasks,
        description: "switch SAST task selection",
    },
    ShellCommandSpec {
        command: "task reset",
        aliases: &["/task reset"],
        category: ShellCommandCategory::OptionsTasks,
        description: "reset SAST task state",
    },
];
