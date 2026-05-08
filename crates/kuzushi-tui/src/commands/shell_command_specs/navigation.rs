use super::*;

pub(crate) const NAVIGATION_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "help",
        aliases: &["/help", "/h", "h", "?"],
        category: ShellCommandCategory::Navigation,
        description: "show grouped shell help",
    },
    ShellCommandSpec {
        command: "modules",
        aliases: &["/modules", "/m", "m", "show modules"],
        category: ShellCommandCategory::Navigation,
        description: "browse native Rust modules",
    },
    ShellCommandSpec {
        command: "tools",
        aliases: &["/tools", "show tools"],
        category: ShellCommandCategory::Navigation,
        description: "list routed Rust tools",
    },
    ShellCommandSpec {
        command: "use <module>",
        aliases: &["use semgrep", "/use <module>"],
        category: ShellCommandCategory::Navigation,
        description: "focus a module",
    },
    ShellCommandSpec {
        command: "back",
        aliases: &["/back", "/b", "b"],
        category: ShellCommandCategory::Navigation,
        description: "return to the previous view",
    },
    ShellCommandSpec {
        command: "quickstart",
        aliases: &["/quickstart"],
        category: ShellCommandCategory::Navigation,
        description: "first-run guided setup",
    },
];
