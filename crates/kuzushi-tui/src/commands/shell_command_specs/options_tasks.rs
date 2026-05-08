use super::*;

pub(crate) const OPTIONS_TASK_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "options [tool]",
        aliases: &["/options [tool]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "show tool options",
    },
    ShellCommandSpec {
        command: "show options [tool]",
        aliases: &["/show options [tool]"],
        category: ShellCommandCategory::OptionsTasks,
        description: "show tool options",
    },
    ShellCommandSpec {
        command: "show advanced",
        aliases: &["/show advanced"],
        category: ShellCommandCategory::OptionsTasks,
        description: "advanced and evasion options",
    },
    ShellCommandSpec {
        command: "show missing",
        aliases: &["/show missing"],
        category: ShellCommandCategory::OptionsTasks,
        description: "required options without values",
    },
    ShellCommandSpec {
        command: "set <key> <value>",
        aliases: &["/set <key> <value>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "set a session option",
    },
    ShellCommandSpec {
        command: "setg <key> <value>",
        aliases: &["/setg <key> <value>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "set a global option",
    },
    ShellCommandSpec {
        command: "unset <key>",
        aliases: &["/unset <key>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "clear a session option",
    },
    ShellCommandSpec {
        command: "unsetg <key>",
        aliases: &["/unsetg <key>"],
        category: ShellCommandCategory::OptionsTasks,
        description: "clear a global option",
    },
    ShellCommandSpec {
        command: "tasks",
        aliases: &["/tasks"],
        category: ShellCommandCategory::OptionsTasks,
        description: "choose SAST scanner tasks",
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
