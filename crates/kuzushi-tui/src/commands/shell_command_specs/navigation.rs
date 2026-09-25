use super::*;

pub(crate) const NAVIGATION_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "home",
        aliases: &["/home", "/", "home"],
        category: ShellCommandCategory::Navigation,
        description: "open the current phase cockpit",
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
        description: "open the current Map/Scan/Review/Prove/Fix phase",
    },
    ShellCommandSpec {
        command: "report",
        aliases: &["report", "/report"],
        category: ShellCommandCategory::Navigation,
        description: "export the engagement report with a durable receipt",
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
        description: "open phase-native capabilities (press e for expert engines)",
    },
    ShellCommandSpec {
        command: "recommend",
        aliases: &["recommend", "/recommend", "rec", "/rec"],
        category: ShellCommandCategory::Navigation,
        description: "open phase-native recommended capabilities",
    },
    ShellCommandSpec {
        command: "tools [query]",
        aliases: &["/tools", "show tools", "tools semgrep", "tools --fav"],
        category: ShellCommandCategory::Navigation,
        description: "list or filter routed Rust tools",
    },
    ShellCommandSpec {
        command: "find [query]",
        aliases: &["/find", "find phase:scan taint"],
        category: ShellCommandCategory::Navigation,
        description: "open the Tools view grammar-first (alias for tools [query])",
    },
    ShellCommandSpec {
        command: "favorite <tool>",
        aliases: &["/favorite <tool>", "fav <tool>", "/fav <tool>"],
        category: ShellCommandCategory::Navigation,
        description: "toggle a tool on the per-workspace YOUR TOOLS shelf",
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
        description: "filter the expert tool inventory by module",
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
        command: "setup",
        aliases: &["/setup", "onboarding", "/onboarding", "/planning"],
        category: ShellCommandCategory::Navigation,
        description: "review target, Map plan, model/credentials, prompt, and budget readiness",
    },
    // Keep the typed alias visible without adding `/continue`, which would
    // shadow `/context` in Tab completion for `/con…`.
    ShellCommandSpec {
        command: "next [fresh]",
        aliases: &["next", "/next"],
        category: ShellCommandCategory::Navigation,
        description: "continue the engagement (alias: continue) — open the derived phase's picker; `next fresh` restarts the pass at the Map planner",
    },
    ShellCommandSpec {
        command: "map",
        aliases: &["/map", "/ma"],
        category: ShellCommandCategory::Navigation,
        description: "open the Map page once map is complete or passed; otherwise its planner",
    },
    ShellCommandSpec {
        command: "scan",
        aliases: &["/scan", "/sc"],
        category: ShellCommandCategory::Navigation,
        description: "open the Scan page once scan is complete or passed; otherwise its planner",
    },
    ShellCommandSpec {
        command: "scan batch",
        aliases: &["/scan batch", "scan batch --prior-run <runId>"],
        category: ShellCommandCategory::Navigation,
        description: "configure repeated logical scan trials, optionally costed from a prior run",
    },
    ShellCommandSpec {
        command: "batch <id>",
        aliases: &["/batch <id>"],
        category: ShellCommandCategory::Navigation,
        description: "open one scan batch's occurrence results and gate receipt",
    },
    ShellCommandSpec {
        command: "batch clear",
        aliases: &["/batch clear"],
        category: ShellCommandCategory::Navigation,
        description: "clear the active scan-batch results scope",
    },
    ShellCommandSpec {
        command: "review",
        aliases: &["/review", "/rv"],
        category: ShellCommandCategory::Navigation,
        description: "open the Review page once review is complete or passed; otherwise its planner",
    },
    ShellCommandSpec {
        command: "prove",
        aliases: &["/prove", "/pr"],
        category: ShellCommandCategory::Navigation,
        description: "open the Prove page once prove is complete or passed; otherwise its planner",
    },
    ShellCommandSpec {
        command: "fix",
        aliases: &["/fix", "/fx"],
        category: ShellCommandCategory::Navigation,
        description: "open the Fix page once fix is complete or passed; otherwise its planner",
    },
    ShellCommandSpec {
        command: "phase <map|scan|review|prove|fix>",
        aliases: &[
            "phase map",
            "phase scan",
            "phase review",
            "phase prove",
            "phase fix",
            // Compatibility aliases for the v0.1 four-phase vocabulary.
            "phase hunt",
            "phase confirm",
        ],
        category: ShellCommandCategory::Navigation,
        description: "open a specific engagement phase picker",
    },
    ShellCommandSpec {
        command: "plan <map|scan|review|prove|fix>",
        aliases: &["/plan <map|scan|review|prove|fix>", "plan map", "plan fix"],
        category: ShellCommandCategory::Navigation,
        description: "always open that phase's planner, even when the phase is complete",
    },
    ShellCommandSpec {
        command: "autonomy [recon|scan|review|prove|fix]",
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
    ShellCommandSpec {
        command: "background",
        aliases: &["/background", "bg", "/bg"],
        category: ShellCommandCategory::Navigation,
        description: "drop to Workbench, keep the job running (Ctrl+C still cancels)",
    },
];
