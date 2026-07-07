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
        command: "workbench",
        aliases: &["/workbench", "workbench"],
        category: ShellCommandCategory::Navigation,
        description: "open the split-pane command center",
    },
    ShellCommandSpec {
        command: "aim [focus]",
        aliases: &["aim", "/aim", "aim sqli", "aim idor"],
        category: ShellCommandCategory::Navigation,
        description: "seed the engagement harness from the Workbench AIM page",
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
        command: "tools [query]",
        aliases: &["/tools", "show tools", "tools semgrep"],
        category: ShellCommandCategory::Navigation,
        description: "list or filter routed Rust tools",
    },
    ShellCommandSpec {
        command: "doctor",
        aliases: &["/doctor", "health", "/health"],
        category: ShellCommandCategory::Navigation,
        description: "show shell preflight health",
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
        aliases: &["/onboarding", "/planning"],
        category: ShellCommandCategory::Navigation,
        description: "open the planning-stage multi-select picker",
    },
    // Keep the typed alias visible without adding `/continue`, which would
    // shadow `/context` in Tab completion for `/con…`.
    ShellCommandSpec {
        command: "next",
        aliases: &["next", "/next"],
        category: ShellCommandCategory::Navigation,
        description: "continue the engagement (alias: continue) — open the current phase's picker",
    },
    ShellCommandSpec {
        command: "phase <map|hunt|confirm|fix>",
        aliases: &["phase map", "phase hunt", "phase confirm", "phase fix"],
        category: ShellCommandCategory::Navigation,
        description: "open a specific engagement phase picker",
    },
    ShellCommandSpec {
        command: "autonomy [recon|hunt|confirm|fix]",
        aliases: &["autonomy", "/autonomy", "posture", "/posture"],
        category: ShellCommandCategory::Navigation,
        description: "read/set the autonomy dial (also Ctrl+Up/Down) — the tool-dispatch ceiling",
    },
    ShellCommandSpec {
        command: "logs",
        aliases: &["/logs", "log", "transcript", "/transcript"],
        category: ShellCommandCategory::Navigation,
        description: "scrollable full-screen transcript",
    },
];
