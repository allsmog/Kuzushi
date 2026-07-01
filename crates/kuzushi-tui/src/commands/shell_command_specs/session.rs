use super::*;

pub(crate) const SESSION_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "history",
        aliases: &["/history"],
        category: ShellCommandCategory::Session,
        description: "show command history",
    },
    ShellCommandSpec {
        command: "clear",
        aliases: &["/clear"],
        category: ShellCommandCategory::Session,
        description: "clear conversation log",
    },
    ShellCommandSpec {
        command: "load <specifier>",
        aliases: &["/load <specifier>"],
        category: ShellCommandCategory::Session,
        description: "static registry status or load error",
    },
    ShellCommandSpec {
        command: "pause",
        aliases: &["/pause"],
        category: ShellCommandCategory::Session,
        description: "document live-control absence",
    },
    ShellCommandSpec {
        command: "cancel",
        aliases: &["/cancel", "c", "/c", "stop", "/stop"],
        category: ShellCommandCategory::Session,
        description: "cancel the active scan/tool/agent without leaving the shell",
    },
    ShellCommandSpec {
        command: "resume [runId]",
        aliases: &["/resume [runId]"],
        category: ShellCommandCategory::Session,
        description: "document checkpoint-resume absence",
    },
    ShellCommandSpec {
        command: "story",
        aliases: &["/story"],
        category: ShellCommandCategory::Session,
        description: "show session story replacements",
    },
    ShellCommandSpec {
        command: "prompts",
        aliases: &["/prompts", "show prompts"],
        category: ShellCommandCategory::Session,
        description: "prompt override view",
    },
    ShellCommandSpec {
        command: "prompt <verb>",
        aliases: &["/prompt <verb>"],
        category: ShellCommandCategory::Session,
        description: "prompt editor action",
    },
    ShellCommandSpec {
        command: "tune",
        aliases: &["/tune", "/t", "t"],
        category: ShellCommandCategory::Session,
        description: "module controls",
    },
    ShellCommandSpec {
        command: "actor <n>",
        aliases: &["/actor <n>"],
        category: ShellCommandCategory::Session,
        description: "actor transcript detail",
    },
    ShellCommandSpec {
        command: "plan <english>",
        aliases: &["/plan <english>"],
        category: ShellCommandCategory::Session,
        description: "Haiku natural-language planner; review then /yes or /no",
    },
    ShellCommandSpec {
        command: "yes",
        aliases: &["/yes", "y"],
        category: ShellCommandCategory::Session,
        description: "apply pending plan",
    },
    ShellCommandSpec {
        command: "no",
        aliases: &["/no", "n"],
        category: ShellCommandCategory::Session,
        description: "discard pending plan",
    },
    ShellCommandSpec {
        command: "scene",
        aliases: &["/scene", "/viz", "viz", "/diagram"],
        category: ShellCommandCategory::Session,
        description: "security-viz gallery — risk heatmap, attack path/tree, DFD",
    },
    ShellCommandSpec {
        command: "quit",
        aliases: &["q", "/q", "exit", "/quit", "/exit"],
        category: ShellCommandCategory::Session,
        description: "exit the shell",
    },
];
