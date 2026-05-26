use super::*;

pub(crate) const AUTH_CONFIG_MODEL_COMMANDS: &[ShellCommandSpec] = &[
    ShellCommandSpec {
        command: "auth",
        aliases: &["/auth", "auth status"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show env/OAuth status without secrets",
    },
    ShellCommandSpec {
        command: "auth login <provider> [method]",
        aliases: &[
            "/auth login openai",
            "/auth login anthropic",
            "/auth login github-copilot",
        ],
        category: ShellCommandCategory::AuthConfigModel,
        description: "start supported OAuth login flow",
    },
    ShellCommandSpec {
        command: "provider",
        aliases: &["/provider"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show pi-agent-core provider choices",
    },
    ShellCommandSpec {
        command: "backend",
        aliases: &["/backend"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show Rust runtime backend",
    },
    ShellCommandSpec {
        command: "model [choice]",
        aliases: &["model 1", "/model [choice]"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "select explicit provider:model",
    },
    ShellCommandSpec {
        command: "cost",
        aliases: &["/cost"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show known session cost estimate",
    },
    ShellCommandSpec {
        command: "config",
        aliases: &["/config"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show runtime config status",
    },
    ShellCommandSpec {
        command: "permissions",
        aliases: &["/permissions", "show permissions"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "show approval and sandbox policy",
    },
    ShellCommandSpec {
        command: "target [path]",
        aliases: &["/target [path]"],
        category: ShellCommandCategory::AuthConfigModel,
        description: "switch scan target without restart",
    },
];
