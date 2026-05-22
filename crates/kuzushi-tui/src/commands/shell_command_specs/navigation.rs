use super::*;

pub(crate) const NAVIGATION_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "home",
        aliases: &["/home", "/", "home"],
        category: ShellCommandCategory::Navigation,
        description: "open Kuzushi cockpit home",
    },
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
        command: "recommend",
        aliases: &["recommend", "/recommend", "rec", "/rec"],
        category: ShellCommandCategory::Navigation,
        description: "open latest module recommendations",
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
    ShellCommandSpec {
        command: "onboarding",
        aliases: &["/onboarding", "/setup", "/planning", "/plan-stage"],
        category: ShellCommandCategory::Navigation,
        description: "open the planning-stage multi-select picker",
    },
];
